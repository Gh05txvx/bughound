# syntax=docker/dockerfile:1
#
# Image bughound multi-target: satu Dockerfile, tiga image berbeda toolchain.
# Karena adapter memanggil engine/tool sebagai subprocess di PATH, menaruhnya di
# image = langsung jalan tanpa pasang apa pun di host.
#
#   docker build --target dast  -t bughound:dast .        # DAST+recon, tanpa SAST (ramping, butuh egress)
#   docker build --target sast  -t bughound:sast .        # SAST (semgrep+bandit+gitleaks), tanpa jaringan
#   docker build               -t bughound:full .         # keduanya (target default)
#
# Build-arg DAST (dipakai target dast & full):
#   --build-arg WITH_ZAP=true       (+JRE, ~500MB; DAST aktif ZAP)
#   --build-arg WITH_RETIRE=true    (+Node; SCA library JS klien)
# Build-arg SAST (dipakai target sast & full):
#   --build-arg WITH_FINDSECBUGS=true   (+JRE+SpotBugs; SAST bytecode JVM)

# --- Stage: build binary bughound ---
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/bughound ./cmd/bughound

# --- Stage: engine CLI berbasis Go (ter-isolasi agar cache rapi) ---
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
 && go install github.com/ffuf/ffuf/v2@latest \
 && go install github.com/hahwul/dalfox/v2@v2.13.0

# --- Stage: assets (unduh aset build-time; tak ikut ke runtime) ---
# Wordlist route API (Assetnote "apiroutes") dinormalkan di sini lalu DI-COPY ke
# image DAST, sehingga image runtime tak perlu python/curl hanya untuk unduh ini.
# Fail-closed: unduh gagal / isi kurang => build gagal keras.
FROM debian:bookworm-slim AS assets
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    mkdir -p /assets; \
    curl -fsSL -A bughound-build "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2025_06_28.txt" -o /tmp/apiroutes.raw; \
    sed -e 's/\r$//' -e 's/?.*$//' -e 's#^/*##' -e 's#/*$##' /tmp/apiroutes.raw \
      | grep -vE '^$|^#|[[:space:]]|\*|\$' \
      | awk '!seen[$0]++' \
      | head -n 10000 > /assets/apiroutes.txt; \
    rm -f /tmp/apiroutes.raw; \
    test "$(wc -l < /assets/apiroutes.txt)" -ge 1000

# --- Stage: base (runtime bersama semua target) ---
FROM debian:bookworm-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
# Jalan sebagai non-root; data (db, kunci, anchor) di /data.
RUN useradd -m -u 10001 bh && mkdir -p /data && chown bh:bh /data
WORKDIR /data
EXPOSE 8787
# Default AMAN: bind 0.0.0.0 (untuk -p docker) TAPI engine mock (tak ada scan
# nyata). Untuk DAST nyata (image dast/full): override -engine nuclei,ffuf,zap...
ENTRYPOINT ["bughound"]
CMD ["-addr", "0.0.0.0:8787", "-db", "/data/bughound.db"]

# --- Stage: dast-tools (engine DAST+recon; induk bersama dast & full) ---
# TANPA binary bughound di sini — binary disalin TERAKHIR di tiap leaf agar
# perubahan source tak membatalkan layer toolchain yang mahal.
FROM base AS dast-tools
ARG WITH_ZAP=false
# ZAP: versi di-pin + SHA-256 diverifikasi (fail-closed bila checksum tak cocok).
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
# retire.js opsional. Node bookworm = 18.x; retire 6.x butuh Node >=20, jadi 5.x.
ARG WITH_RETIRE=false
ARG RETIRE_VERSION=5.7.0
USER root
# libpcap0.8 = runtime naabu.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=engines /engines/ /usr/local/bin/
COPY --from=assets /assets/apiroutes.txt /usr/local/share/bughound/wordlists/apiroutes.txt
RUN chmod 0644 /usr/local/share/bughound/wordlists/apiroutes.txt
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
# retire.js opsional (butuh Node + npm). fail-closed bila `retire --version` gagal.
RUN if [ "$WITH_RETIRE" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends nodejs npm; \
      npm install -g retire@${RETIRE_VERSION}; \
      npm cache clean --force; \
      retire --version; \
      apt-get clean; rm -rf /var/lib/apt/lists/*; \
    fi
USER bh
# Pre-bake nuclei-templates (sumber 'trusted' repo resmi projectdiscovery) agar
# runtime tak perlu — dan dengan egress terkunci TAK BISA — menariknya. Sebagai
# user 'bh' agar mendarat di $HOME (/home/bh/nuclei-templates), lokasi default.
# Fail-closed: unduh gagal => build gagal keras.
RUN nuclei -update-templates

# --- Stage: dast (DAST image final) ---
FROM dast-tools AS dast
USER root
COPY --from=build /out/bughound /usr/local/bin/bughound
USER bh

# --- Stage: sast-tools (toolchain SAST; induk sast) ---
FROM base AS sast-tools
ARG WITH_FINDSECBUGS=false
USER root
COPY scripts/docker-sast-install.sh /tmp/docker-sast-install.sh
RUN WITH_FINDSECBUGS="$WITH_FINDSECBUGS" sh /tmp/docker-sast-install.sh && rm -f /tmp/docker-sast-install.sh
# SAST semgrep offline (ruleset lokal pre-bake) + SAST aktif default ke /data/sast
# (bughound membuat dir saat boot bila belum ada; path-scope, default-deny).
ENV BUGHOUND_SEMGREP_CONFIG=/opt/semgrep/default.yml \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    BUGHOUND_SAST_ROOT=/data/sast
USER bh

# --- Stage: sast (SAST image final) ---
FROM sast-tools AS sast
USER root
COPY --from=build /out/bughound /usr/local/bin/bughound
USER bh

# --- Stage: full (DAST + SAST; target default) ---
# FROM dast-tools agar layer engine/template di-cache bersama image `dast`; lalu
# tambahkan toolchain SAST. Binary disalin TERAKHIR.
FROM dast-tools AS full
ARG WITH_FINDSECBUGS=false
USER root
COPY scripts/docker-sast-install.sh /tmp/docker-sast-install.sh
RUN WITH_FINDSECBUGS="$WITH_FINDSECBUGS" sh /tmp/docker-sast-install.sh && rm -f /tmp/docker-sast-install.sh
# Pulihkan biner engine projectdiscovery SETELAH install SAST: pip (dependensi
# semgrep) memasang CLI `httpx` Python ke /usr/local/bin/httpx yang menimpa httpx
# recon. COPY ulang engines agar tool DAST yang menang (hanya di image full).
COPY --from=engines /engines/ /usr/local/bin/
ENV BUGHOUND_SEMGREP_CONFIG=/opt/semgrep/default.yml \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    BUGHOUND_SAST_ROOT=/data/sast
COPY --from=build /out/bughound /usr/local/bin/bughound
USER bh
