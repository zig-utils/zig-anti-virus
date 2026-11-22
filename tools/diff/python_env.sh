#!/bin/sh
# A Python virtual environment for the differential tools, first on PATH for the steps after it.
#
#   sh tools/diff/python_env.sh [PACKAGE...]
#
# The first python3 that actually runs and can make a venv, rather than whichever is first on
# PATH: a self-hosted runner (ReviewOS) may carry a python3 that cannot load its own library.
# Where the venv module has no pip (Debian without python3-venv), pip is bootstrapped into it.
set -eu

dir="$RUNNER_TEMP/py"
py=""
for candidate in python3 /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import venv' >/dev/null 2>&1; then
    py="$candidate"
    break
  fi
done
[ -n "$py" ] || { echo "No working python3 with the venv module on this runner" >&2; exit 1; }

if ! "$py" -m venv "$dir" >/dev/null 2>&1; then
  rm -rf "$dir"
  "$py" -m venv --without-pip "$dir"
  curl -fsSL --retry 3 https://bootstrap.pypa.io/get-pip.py | "$dir/bin/python3" - --quiet
fi
if [ "$#" -gt 0 ]; then
  "$dir/bin/python3" -m pip install --quiet "$@"
fi
echo "$dir/bin" >> "$GITHUB_PATH"
"$dir/bin/python3" --version
