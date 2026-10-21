#!/bin/bash
# scripts/build.sh [out] - build Janus as one file: a Python zipapp (standard library only) with a python3 shebang.
#   bash scripts/build.sh              -> dist/janus          bash scripts/build.sh /tmp/janus   -> that path
# Install it as ~/.local/bin/janus on the server (bash scripts/install.sh). Needs only python3.
set -e
R=$(cd "$(dirname "$0")/.." && pwd); V=$(cat "$R/VERSION"); OUT=${1:-$R/dist/janus}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/app" "$(dirname "$OUT")"
cp -r "$R/janus" "$T/app/janus"; find "$T/app" -name __pycache__ -type d -exec rm -rf {} +
echo "$V" > "$T/app/janus/VERSION"               # janus.version() reads it from inside the archive
cp "$R/janus/__main__.py" "$T/app/__main__.py"   # the zipapp's entry point: sys.exit(main())
python3 -m zipapp "$T/app" -o "$OUT" -p "/usr/bin/env python3" -c
chmod +x "$OUT"
echo "built $OUT (janus $V, $(du -h "$OUT" | cut -f1))"
