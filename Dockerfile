# syntax=docker/dockerfile:1
#
# Multi-target bughound image: one Dockerfile, three images with different toolchains.
# Because the adapters call the engine/tool as a subprocess on PATH, putting them in
# the image = they run right away without installing anything on the host.
#
#   docker build --target dast  -t bughound:dast .        # DAST+recon, no SAST (lean, needs egress)
#   docker build --target sast  -t bughound:sast .        # SAST (semgrep+bandit+gitleaks), no network
#   docker build               -t bughound:full .         # both (the default target)
#
# DAST build-args (used by the dast & full targets):
#   --build-arg WITH_ZAP=true       (+JRE, ~500MB; DAST runs ZAP)
#   --build-arg WITH_RETIRE=true    (+Node; SCA for client-side JS libraries)
# SAST build-args (used by the sast & full targets):
#   --build-arg WITH_FINDSECBUGS=true   (+JRE+SpotBugs; SAST on JVM bytecode)

# --- Stage: build binary bughound ---
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/bughound ./cmd/bughound

# --- Stage: Go-based engine CLIs (isolated so the cache stays clean) ---
FROM golang:1.27-bookworm AS engines
ENV GOBIN=/engines
# libpcap-dev is needed to build naabu (gopacket).
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

# --- Stage: assets (download build-time assets; not carried into runtime) ---
# The API route wordlist (Assetnote "apiroutes") is normalized here then COPIED into
# the DAST image, so the runtime image needs no python/curl just to download it.
# Fail-closed: a failed download / short content => a hard build failure.
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

# --- Stage: base (runtime shared by every target) ---
FROM debian:bookworm-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
# Run as non-root; data (db, keys, anchors) in /data.
RUN useradd -m -u 10001 bh && mkdir -p /data && chown bh:bh /data
WORKDIR /data
EXPOSE 8787
# SAFE default: bind 0.0.0.0 (for docker -p) BUT mock engines (no real
# scan). For real DAST (the dast/full image): override -engine nuclei,ffuf,zap...
ENTRYPOINT ["bughound"]
CMD ["-addr", "0.0.0.0:8787", "-db", "/data/bughound.db"]

# --- Stage: dast-tools (DAST+recon engines; the shared parent of dast & full) ---
# NO bughound binary here, the binary is copied LAST in each leaf so a
# source change does not invalidate the expensive toolchain layers.
FROM base AS dast-tools
ARG WITH_ZAP=false
# ZAP: version pinned + SHA-256 verified (fail-closed if the checksum does not match).
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
# retire.js is optional. Node bookworm = 18.x; retire 6.x needs Node >=20, so 5.x.
ARG WITH_RETIRE=false
ARG RETIRE_VERSION=5.7.0
USER root
# libpcap0.8 = runtime naabu.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=engines /engines/ /usr/local/bin/
COPY --from=assets /assets/apiroutes.txt /usr/local/share/bughound/wordlists/apiroutes.txt
RUN chmod 0644 /usr/local/share/bughound/wordlists/apiroutes.txt
# ZAP optional (needs a JRE; adds ~500MB). Not installed by default.
RUN if [ "$WITH_ZAP" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends default-jre-headless curl; \
      curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -o /tmp/zap.tgz; \
      echo "${ZAP_SHA256}  /tmp/zap.tgz" | sha256sum -c -; \
      tar -xzf /tmp/zap.tgz -C /opt; rm /tmp/zap.tgz; \
      ln -s "/opt/ZAP_${ZAP_VERSION}/zap.sh" /usr/local/bin/zap.sh; \
      apt-get clean; rm -rf /var/lib/apt/lists/*; \
    fi
# retire.js optional (needs Node + npm). fail-closed if `retire --version` fails.
RUN if [ "$WITH_RETIRE" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends nodejs npm; \
      npm install -g retire@${RETIRE_VERSION}; \
      npm cache clean --force; \
      retire --version; \
      apt-get clean; rm -rf /var/lib/apt/lists/*; \
    fi
USER bh
# Pre-bake the nuclei-templates (a 'trusted' source, projectdiscovery's official repo) so
# the runtime does not need to, and with egress locked down CANNOT, pull them. As the
# 'bh' user so they land in $HOME (/home/bh/nuclei-templates), the default location.
# Fail-closed: a failed download => a hard build failure.
RUN nuclei -update-templates

# --- Stage: dast (DAST image final) ---
FROM dast-tools AS dast
USER root
COPY --from=build /out/bughound /usr/local/bin/bughound
USER bh

# --- Stage: sast-tools (SAST toolchain; the parent of sast) ---
FROM base AS sast-tools
ARG WITH_FINDSECBUGS=false
USER root
COPY scripts/docker-sast-install.sh /tmp/docker-sast-install.sh
RUN WITH_FINDSECBUGS="$WITH_FINDSECBUGS" sh /tmp/docker-sast-install.sh && rm -f /tmp/docker-sast-install.sh
# semgrep SAST offline (a pre-baked local ruleset) + SAST on by default at /data/sast
# (bughound creates the dir at boot if missing; path-scoped, default-deny).
ENV BUGHOUND_SEMGREP_CONFIG=/opt/semgrep/default.yml \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    BUGHOUND_SAST_ROOT=/data/sast
USER bh

# --- Stage: sast (SAST image final) ---
FROM sast-tools AS sast
USER root
COPY --from=build /out/bughound /usr/local/bin/bughound
USER bh

# --- Stage: full (DAST + SAST; the default target) ---
# FROM dast-tools so the engine/template layers are cached together with the `dast`
# image; then add the SAST toolchain. The binary is copied LAST.
FROM dast-tools AS full
ARG WITH_FINDSECBUGS=false
USER root
COPY scripts/docker-sast-install.sh /tmp/docker-sast-install.sh
RUN WITH_FINDSECBUGS="$WITH_FINDSECBUGS" sh /tmp/docker-sast-install.sh && rm -f /tmp/docker-sast-install.sh
# Restore the projectdiscovery engine binaries AFTER installing SAST: pip (a semgrep
# dependency) drops a Python `httpx` CLI into /usr/local/bin/httpx that overwrites the
# recon httpx. Re-COPY the engines so the DAST tool wins (full image only).
COPY --from=engines /engines/ /usr/local/bin/
ENV BUGHOUND_SEMGREP_CONFIG=/opt/semgrep/default.yml \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    BUGHOUND_SAST_ROOT=/data/sast
COPY --from=build /out/bughound /usr/local/bin/bughound
USER bh
