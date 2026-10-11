#!/bin/sh
set -eu
desktop_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
desktop_node="${ZARK_NODE:-$(command -v node)}"
if [ ! -x "$desktop_node" ]; then echo 'Node.js 20+ is required for desktop tests.' >&2; exit 1; fi
exec "$desktop_node" --test "$desktop_dir"/runtime/*.test.mjs "$desktop_dir"/relay/*.test.mjs "$desktop_dir"/../desktop-tauri/test/*.test.mjs
