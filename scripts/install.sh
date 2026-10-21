#!/bin/bash
# scripts/install.sh [dest] - build the zipapp and copy it to ~/.local/bin/janus (or dest) on this machine. Needs python3.
# It installs only the one file; the config (~/.config/janus/routes.json, doors.json) is copied from the private realm
# repo by its own deploy, never by this script.
set -e
R=$(cd "$(dirname "$0")/.." && pwd); DEST=${1:-$HOME/.local/bin/janus}
bash "$R/scripts/build.sh" "$R/dist/janus"
mkdir -p "$(dirname "$DEST")"
cp "$R/dist/janus" "$DEST.new" && chmod +x "$DEST.new" && mv -f "$DEST.new" "$DEST"
echo "installed $DEST ($("$DEST" --version))"
