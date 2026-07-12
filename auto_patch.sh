#!/usr/bin/env bash
set -euo pipefail

API="${STUDIO_PATCHER_API:-https://ccc-backend-1.onrender.com}"
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
VERSION="$(defaults read "$APP/Contents/Info.plist" CFBundleVersion)"
BINARY="$APP/Contents/MacOS/$BIN_NAME"

[ -f "$BINARY" ] || { echo "error: binary not found at $BINARY" >&2; exit 1; }

RESPONSE="$(curl -fsS "$API/studio-patcher/globals/$VERSION")" || {
  echo "error: no globals published for build $VERSION yet, try again later" >&2
  exit 1
}
GLOBALS="$(grep -o '0x[0-9a-fA-F]*' <<<"$RESPONSE" | paste -sd, -)"
[ -n "$GLOBALS" ] || { echo "error: bad response from $API" >&2; exit 1; }

"$STUDIO_PATCHER" --binary "$APP" --globals "$GLOBALS"
