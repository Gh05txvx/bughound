#!/bin/sh
# Pemasang toolchain SAST untuk image bughound (dipakai target `sast` & `full`).
# Dipisah ke skrip agar langkahnya tak terduplikasi di dua stage Dockerfile.
#
# Memasang: semgrep + bandit (pip), gitleaks (biner rilis resmi, checksum
# diverifikasi), ruleset semgrep `p/default` di-pre-bake offline. findsecbugs
# (SpotBugs + plugin, butuh JRE) opsional via WITH_FINDSECBUGS=true.
#
# Semua unduhan fail-closed: checksum tak cocok / tool tak jalan => build gagal
# keras (bukan diam-diam mengirim image tanpa tool).
set -eux

WITH_FINDSECBUGS="${WITH_FINDSECBUGS:-false}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"
SPOTBUGS_VERSION="${SPOTBUGS_VERSION:-4.8.6}"
FINDSECBUGS_VERSION="${FINDSECBUGS_VERSION:-1.13.0}"

apt-get update
apt-get install -y --no-install-recommends ca-certificates python3 python3-pip curl

# semgrep + bandit (SAST Python & multi-bahasa) via pip.
pip3 install --no-cache-dir --break-system-packages semgrep bandit

# gitleaks (deteksi secret) — biner rilis resmi, checksum diverifikasi.
arch="$(dpkg --print-architecture)"
case "$arch" in
  amd64) glarch="x64" ;;
  arm64) glarch="arm64" ;;
  *) echo "arsitektur gitleaks tak didukung: $arch" >&2; exit 1 ;;
esac
gltar="gitleaks_${GITLEAKS_VERSION}_linux_${glarch}.tar.gz"
base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
curl -fsSL "${base}/${gltar}" -o /tmp/gitleaks.tgz
curl -fsSL "${base}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" -o /tmp/gitleaks.sums
# Verifikasi hanya berkas yang kita unduh (checksums.txt memuat semua arch).
grep " ${gltar}\$" /tmp/gitleaks.sums | sed "s# .*# /tmp/gitleaks.tgz#" | sha256sum -c -
tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks
chmod 0755 /usr/local/bin/gitleaks
rm -f /tmp/gitleaks.tgz /tmp/gitleaks.sums
gitleaks version

# Pre-bake ruleset semgrep `p/default` ke berkas lokal → SAST semgrep JALAN
# OFFLINE (egress runtime dikunci scope guard). Fail-closed: unduh/validasi gagal
# => build gagal keras. Berkas world-readable agar user runtime 'bh' bisa baca.
mkdir -p /opt/semgrep
python3 -c "import urllib.request; r=urllib.request.Request('https://semgrep.dev/c/p/default', headers={'User-Agent':'bughound-build'}); open('/opt/semgrep/default.yml','wb').write(urllib.request.urlopen(r, timeout=120).read())"
semgrep --validate --config /opt/semgrep/default.yml --metrics=off
chmod 0644 /opt/semgrep/default.yml

# findsecbugs (SpotBugs + plugin) OPSIONAL — analisis bytecode JVM, butuh JRE.
if [ "$WITH_FINDSECBUGS" = "true" ]; then
  apt-get install -y --no-install-recommends default-jre-headless unzip
  curl -fsSL "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz" -o /tmp/spotbugs.tgz
  tar -xzf /tmp/spotbugs.tgz -C /opt
  ln -s "/opt/spotbugs-${SPOTBUGS_VERSION}/bin/spotbugs" /usr/local/bin/spotbugs
  rm -f /tmp/spotbugs.tgz
  mkdir -p /opt/findsecbugs
  curl -fsSL "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar" -o /opt/findsecbugs/findsecbugs-plugin.jar
  test -s /opt/findsecbugs/findsecbugs-plugin.jar
  spotbugs -version
fi

# Bersihkan jejak build.
apt-get purge -y curl
apt-get autoremove -y
pip3 cache purge 2>/dev/null || true
apt-get clean
rm -rf /var/lib/apt/lists/*

# Sanity: tool inti harus jalan.
semgrep --version
bandit --version
gitleaks version
