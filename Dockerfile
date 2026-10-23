# syntax=docker/dockerfile:1
#
# Image gabungan: bughound (orchestrator) + engine nyata di dalam satu container.
# Karena adapter memanggil engine sebagai subprocess di PATH, menaruh engine di
# image = `-engine real`/`nuclei,ffuf,zap` langsung jalan tanpa pasang apa pun di host.
#
# Build (lean, tanpa ZAP):     docker build -t bughound .
# Build + ZAP (berat, +JRE):   docker build --build-arg WITH_ZAP=true -t bughound:zap .

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

# semgrep (SAST) via pip + CA certs + libpcap0.8 (runtime naabu).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 python3-pip libpcap0.8 \
 && pip3 install --no-cache-dir --break-system-packages semgrep \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# ZAP opsional (butuh JRE; menambah ~500MB). Default tidak dipasang.
RUN if [ "$WITH_ZAP" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends default-jre-headless curl; \
      curl -fsSL https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz -o /tmp/zap.tgz; \
      tar -xzf /tmp/zap.tgz -C /opt; rm /tmp/zap.tgz; \
      ln -s /opt/ZAP_2.15.0/zap.sh /usr/local/bin/zap.sh; \
      apt-get clean; rm -rf /var/lib/apt/lists/*; \
    fi

COPY --from=engines /engines/ /usr/local/bin/
COPY --from=build /out/bughound /usr/local/bin/bughound

# Jalan sebagai non-root; data (db, kunci, anchor) di /data.
RUN useradd -m -u 10001 bh && mkdir -p /data && chown bh:bh /data
USER bh
WORKDIR /data
EXPOSE 8787

# Default AMAN: bind 0.0.0.0 (untuk -p docker) TAPI engine mock (tak ada scan
# nyata). Untuk scan nyata, override: ... -engine nuclei,ffuf,zap  (+ -auth).
ENTRYPOINT ["bughound"]
CMD ["-addr", "0.0.0.0:8787", "-db", "/data/bughound.db"]
