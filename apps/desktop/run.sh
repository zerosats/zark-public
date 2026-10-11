#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if [ "${1:-}" = --preview ]; then
  export ZARK_NODE="${ZARK_NODE:-$(command -v node)}" ZARK_PREVIEW=1 ZARK_DESKTOP_RUNTIME="$repo/apps/desktop/runtime/main.mjs"
  cargo +1.95.0 build --locked --manifest-path "$repo/apps/desktop-tauri/Cargo.toml" --target-dir "$repo/apps/desktop-tauri/target"
  exec "$repo/apps/desktop-tauri/target/debug/zark-desktop"
fi
exec "$repo/run-wallet.sh" "$@"
