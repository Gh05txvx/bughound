# syntax=docker/dockerfile:1
#
# Image gabungan: bughound (orchestrator) + engine nyata di dalam satu container.
# Karena adapter memanggil engine sebagai subprocess di PATH, menaruh engine di
# image = `-engine real`/`nuclei,ffuf,zap` langsung jalan tanpa pasang apa pun di host.
#
# Build (lean, tanpa ZAP):       docker build -t bughound .
# Build + ZAP (berat, +JRE):     docker build --build-arg WITH_ZAP=true -t bughound:zap .
# Build + retire.js (SCA, +Node): docker build --build-arg WITH_RETIRE=true -t bughound:retire .

# --- Stage 1: build binary bughound ---
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/bughound ./cmd/bughound

# --- Stage 2: engine CLI berbasis Go (ter-isolasi agar cache rapi) ---
FROM golang:1.27-bookworm AS engines
ENV GOBIN=/engines
# libpcap-dev dibutuhkan untuk mem-build naabu (gopacket).
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest \
 && go install github.com/ffuf/ffuf/v2@latest

# --- Stage 3: runtime ---
FROM debian:bookworm-slim AS runtime
ARG WITH_ZAP=false
# ZAP: versi di-pin + SHA-256 diverifikasi (unduhan pihak ketiga → fail-closed
# bila checksum tak cocok). Bump versi: ganti keduanya (lihat rilis zaproxy).
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
# retire.js (SCA library JS klien) opsional. Node di bookworm = 18.x; retire 6.x
# butuh Node ^20.19||>=22.12, jadi di-pin ke 5.x (engines.node >= 18) yang jalan.
ARG WITH_RETIRE=false
ARG RETIRE_VERSION=5.7.0

# semgrep (SAST) via pip + CA certs + libpcap0.8 (runtime naabu).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 python3-pip libpcap0.8 \
 && pip3 install --no-cache-dir --break-system-packages semgrep \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# ZAP opsional (butuh JRE; menambah ~500MB). Default tidak dipasang.
RUN if [ "$WITH_ZAP" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends default-jre-headless curl; \
      curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -o /tmp/zap.tgz; \
      echo "${ZAP_SHA256}  /tmp/zap.tgz" | sha256sum -c -; \
      tar -xzf /tmp/zap.tgz -C /opt; rm /tmp/zap.tgz; \
      ln -s "/opt/ZAP_${ZAP_VERSION}/zap.sh" /usr/local/bin/zap.sh; \
      apt-get clean; rm -rf /var/lib/apt/lists/*; \
    fi

# retire.js opsional (butuh Node + npm). Default tidak dipasang. Versi di-pin;
# fail-closed: bila install/`retire --version` gagal, build gagal keras.
RUN if [ "$WITH_RETIRE" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends nodejs npm; \
      npm install -g retire@${RETIRE_VERSION}; \
      npm cache clean --force; \
      retire --version; \
      apt-get clean; rm -rf /var/lib/apt/lists/*; \
    fi

COPY --from=engines /engines/ /usr/local/bin/

# Jalan sebagai non-root; data (db, kunci, anchor) di /data.
RUN useradd -m -u 10001 bh && mkdir -p /data && chown bh:bh /data
USER bh
WORKDIR /data

# Pre-bake nuclei-templates saat build (sumber 'trusted' = repo resmi
# projectdiscovery, satu-satunya sumber tepercaya di awal per BH-SPEC-PAYLOAD).
# Dengan template ada di disk, nuclei tak perlu — dan di runtime TAK BISA —
# menariknya sendiri: egress runtime dikunci scope guard (cuma in-scope), jadi
# unduhan template ke GitHub memang akan diblok. Dijalankan sebagai user 'bh'
# agar template + config mendarat di $HOME-nya (/home/bh/nuclei-templates),
# lokasi default yang dibaca nuclei saat scan — sehingga runner tak butuh -t.
# Fail-closed: bila unduh gagal, build gagal keras (bukan diam-diam mengirim
# image tanpa satu pun check). Versi template tercatat di
# ~/.config/nuclei/.templates-config.json untuk ketertelusuran; pinning versi
# yang sebenarnya menyusul di bank payload (Fase 2 BH-SPEC-PAYLOAD).
RUN nuclei -update-templates

# Binary bughound disalin TERAKHIR: perubahan source hanya membatalkan layer ini
# (tak ada layer mahal setelahnya), sehingga bake template di atas tetap ter-cache
# lintas rebuild. COPY berjalan di tingkat builder (file jadi milik root, 0755);
# USER runtime tetap bh dari atas (COPY tak mengubah USER).
COPY --from=build /out/bughound /usr/local/bin/bughound

EXPOSE 8787

# Default AMAN: bind 0.0.0.0 (untuk -p docker) TAPI engine mock (tak ada scan
# nyata). Untuk scan nyata, override: ... -engine nuclei,ffuf,zap  (+ -auth).
ENTRYPOINT ["bughound"]
CMD ["-addr", "0.0.0.0:8787", "-db", "/data/bughound.db"]
