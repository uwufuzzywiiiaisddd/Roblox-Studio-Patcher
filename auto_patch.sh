#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STUDIO_PATCHER="$HERE/target/release/studio-patcher"

command -v brew &>/dev/null || {
  echo "no brew, installing it first"
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  for p in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$p" ] && eval "$("$p" shellenv)"; done
}
command -v brew &>/dev/null || { echo "error: brew install didn't take, grab it from brew.sh and rerun" >&2; exit 1; }
command -v cargo &>/dev/null || { echo "no rust, installing"; brew install rust; }
[ -x "$STUDIO_PATCHER" ] || (cd "$HERE" && cargo build --release)

APP="${1:-/Applications/RobloxStudio.app}"
# Contents/MacOS has other binaries in it too (crash handler, StudioMCP...) so
# the exec name has to come from Info.plist, not just whatever's first there
BIN_NAME="$(defaults read "$APP/Contents/Info.plist" CFBundleExecutable)"
BINARY="$APP/Contents/MacOS/$BIN_NAME"

[ -f "$BINARY" ] || { echo "error: binary not found at $BINARY" >&2; exit 1; }

"$STUDIO_PATCHER" --binary "$APP" --globals auto

REPLY=""
if [ -r /dev/tty ]; then
  echo "custom themes work by patching the binary to load theme jsons off disk" >&2
  read -r -p "enable custom theme support? [y/N] " REPLY < /dev/tty
fi
[[ "$REPLY" =~ ^[Yy]$ ]] && "$STUDIO_PATCHER" --binary "$APP" --themes
