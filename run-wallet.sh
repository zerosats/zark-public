#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
profile=${1:-alice}
case "$profile" in *[!a-z0-9_-]*|''|[!a-z]*) echo 'Usage: ./run-wallet.sh [profile-name]' >&2; exit 2 ;; esac
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64|Linux-x86_64|Linux-aarch64) ;;
  *) echo 'Zark supports Apple Silicon macOS and x86-64/arm64 Linux.' >&2; exit 1 ;;
esac
for tool in cargo node; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing $tool; see docs/building.md" >&2; exit 1; }
done
if [ "$(uname -s)" = Linux ] && ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
  echo 'Install the Linux desktop dependencies in docs/building.md.' >&2; exit 1
fi
exec node "$repo/scripts/launch-wallet.mjs" "$profile"
