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
BINARY="$APP/Contents/MacOS/$BIN_NAME"

[ -f "$BINARY" ] || { echo "error: binary not found at $BINARY" >&2; exit 1; }

LOCAL_VERSION="$(defaults read "$APP/Contents/Info.plist" CFBundleShortVersionString)"


VERSION=""
for log in "$HOME/Library/Logs/Roblox"/RobloxStudioInstaller_*.log; do
  [ -f "$log" ] || continue
  match="$(grep -o "number $LOCAL_VERSION, Guid version-[0-9a-f]*" "$log" 2>/dev/null | tail -1 || true)"
  [ -n "$match" ] && VERSION="${match##*Guid }"
done

if [ -z "$VERSION" ]; then
  CHANNEL="$(plutil -convert json -o - "$HOME/Library/Preferences/com.roblox.RobloxStudioChannel.plist" 2>/dev/null \
    | grep -o '"www.roblox.com":"[^"]*"' | sed 's/.*:"//;s/"$//')"
  CLIENT_API="https://clientsettings.roblox.com/v2/client-version/MacStudio"
  [ -n "$CHANNEL" ] && CLIENT_API="$CLIENT_API/channel/$CHANNEL"
  CLIENT_INFO="$(curl -fsS "$CLIENT_API" 2>/dev/null || echo '{}')"
  REMOTE_VERSION="$(grep -o '"version":"[^"]*"' <<<"$CLIENT_INFO" | sed 's/.*:"//;s/"$//')"
  [ "$REMOTE_VERSION" = "$LOCAL_VERSION" ] && VERSION="$(grep -o '"clientVersionUpload":"[^"]*"' <<<"$CLIENT_INFO" | sed 's/.*:"//;s/"$//')"
fi

if [ -z "$VERSION" ]; then
  echo "error: couldn't resolve a version hash for the installed build ($LOCAL_VERSION)" >&2
  echo "no matching installer log, and Roblox's channel API has moved past this build" >&2
  exit 1
fi

HTTP="$(curl -sS -w '\n%{http_code}' "$API/studio-patcher/globals/$VERSION")"
CODE="${HTTP##*$'\n'}"
RESPONSE="${HTTP%$'\n'*}"

if [ "$CODE" != "200" ]; then
  VERSIONS="$(grep -o '"versions":\[[^]]*\]' <<<"$RESPONSE" | grep -o '"[^"]*"' | tail -n +2 | tr -d '"' | paste -sd, -)"
  echo "error: no globals published for build $VERSION" >&2
  if [ -z "$VERSIONS" ]; then
    echo "nothing published yet at all, try again later" >&2
    exit 1
  fi

  echo "supported versions right now: $VERSIONS" >&2
  echo "grab one of those from https://rdd.latte.to/ and rerun this against it" >&2

  LATEST="${VERSIONS%%,*}"
  REPLY=""
  [ -r /dev/tty ] && read -r -p "or force-patch anyway using the latest published build ($LATEST)? this just fails cleanly if nothing matches [y/N] " REPLY < /dev/tty
  [[ "$REPLY" =~ ^[Yy]$ ]] || exit 1

  RESPONSE="$(curl -fsS "$API/studio-patcher/globals/$LATEST")" || { echo "error: couldn't fetch globals for $LATEST" >&2; exit 1; }
fi

GLOBALS="$(grep -o '0x[0-9a-fA-F]*' <<<"$RESPONSE" | paste -sd, -)"
[ -n "$GLOBALS" ] || { echo "error: bad response from $API" >&2; exit 1; }

"$STUDIO_PATCHER" --binary "$APP" --globals "$GLOBALS"

REPLY=""
if [ -r /dev/tty ]; then
  echo "custom themes work by patching the binary to load theme jsons off disk" >&2
  read -r -p "enable custom theme support? [y/N] " REPLY < /dev/tty
fi
[[ "$REPLY" =~ ^[Yy]$ ]] && "$STUDIO_PATCHER" --binary "$APP" --themes
