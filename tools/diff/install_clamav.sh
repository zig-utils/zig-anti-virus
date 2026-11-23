#!/bin/sh
# Installs the official ClamAV Linux release the differential expectations were recorded with,
# for this machine's architecture (x86_64 or aarch64), and writes CLAMSCAN, CLAMD and
# CLAMAV_CERTS to $GITHUB_ENV for the steps after it.
#
#   sh tools/diff/install_clamav.sh VERSION [--pcre2]
#
# Runs on GitHub's ubuntu runners and on self-hosted Linux runners (ReviewOS) alike:
# - The package comes over plain HTTPS. A public release needs no token, and the job token is
#   only a GitHub token on GitHub.
# - Where the runner may use sudo (GitHub's can), the package is installed with apt as before.
#   Elsewhere it is unpacked into $RUNNER_TEMP and clamscan runs from there; nothing on the host
#   changes.
# - --pcre2 provides libpcre2-8 for `zig build e13`: libpcre2-dev from apt with sudo, otherwise
#   the same package downloaded (`apt-get download` needs no root) and unpacked, with
#   PCRE2_PREFIX written to $GITHUB_ENV for `-Dpcre2=`.
set -eu

version="$1"
pcre2="${2:-}"
arch=$(uname -m)
case "$arch" in
  x86_64 | aarch64) ;;
  arm64) arch=aarch64 ;;
  *) echo "install_clamav.sh: no official ClamAV package for $arch" >&2; exit 1 ;;
esac
deb="$RUNNER_TEMP/clamav-$version.linux.$arch.deb"

curl -fsSL --retry 3 -o "$deb" \
  "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$version/clamav-$version.linux.$arch.deb"

if sudo -n true 2>/dev/null; then
  if [ "$pcre2" = "--pcre2" ]; then
    sudo apt-get install -y "$deb" libpcre2-dev
  else
    sudo apt-get install -y "$deb"
  fi
  clamscan=$(dpkg -L clamav | grep -m1 '/bin/clamscan$')
  clamd=$(dpkg -L clamav | grep -m1 '/s\{0,1\}bin/clamd$')
  certs=$(dirname "$(dpkg -L clamav | grep -m1 '/certs/')")
else
  root="$RUNNER_TEMP/clamav-root"
  rm -rf "$root"
  dpkg-deb -x "$deb" "$root"
  libs=$(dirname "$(find "$root" -name 'libclamav.so*' | head -1)")
  certs=$(dirname "$(find "$root" -path '*/certs/*' -type f | head -1)")
  # The package expects its libraries where apt would have put them, so each program runs
  # through a wrapper that names them.
  for program in clamscan clamd; do
    binary=$(find "$root" -path "*bin/$program" -type f | head -1)
    printf '#!/bin/sh\nLD_LIBRARY_PATH="%s${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" exec "%s" "$@"\n' "$libs" "$binary" > "$root/$program"
    chmod +x "$root/$program"
  done
  clamscan="$root/clamscan"
  clamd="$root/clamd"

  if [ "$pcre2" = "--pcre2" ]; then
    work="$RUNNER_TEMP/pcre2-deb"
    rm -rf "$work" && mkdir -p "$work"
    (cd "$work" && apt-get download libpcre2-dev >/dev/null)
    dpkg-deb -x "$work"/libpcre2-dev_*.deb "$work/root"
    mkdir -p "$RUNNER_TEMP/pcre2/lib"
    cp "$(find "$work/root" -name 'libpcre2-8.a' | head -1)" "$RUNNER_TEMP/pcre2/lib/"
    echo "PCRE2_PREFIX=$RUNNER_TEMP/pcre2" >> "$GITHUB_ENV"
  fi
fi

echo "CLAMSCAN=$clamscan" >> "$GITHUB_ENV"
echo "CLAMD=$clamd" >> "$GITHUB_ENV"
echo "CLAMAV_CERTS=$certs" >> "$GITHUB_ENV"
"$clamscan" --version
"$clamd" --version
