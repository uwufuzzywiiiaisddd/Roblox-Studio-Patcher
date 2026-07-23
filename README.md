# Roblox-Studio-Patcher

Patches Roblox Studio so `HasInternalPermission` always returns true. mac + windows.

## What this actually does

Studio has a hidden internal mode normally reserved for Roblox employees and their "Soothsayer" testers - it unlocks debug tools, experimental features, and internal-only APIs/menus regular developers don't get. `HasInternalPermission` is the check that gates it; this patches it open for everyone.

Related: the command bar's script identity system has an `ElevatedStudioPlugin` identity level alongside the normal ones (`CommandBar`, etc.) - same general concept of elevated/internal access, just a separate mechanism from the permission check this tool patches.

## Usage

Grab the build for your OS from [releases](https://github.com/uwufuzzywiiiaisddd/Roblox-Studio-Patcher/releases).

**mac (arm64):**

```bash
chmod +x Roblox-Studio-Patcher-mac-silicon
./Roblox-Studio-Patcher-mac-silicon                          # patches /Applications/RobloxStudio.app
./Roblox-Studio-Patcher-mac-silicon --binary /path/to/RobloxStudio.app # or a custom path
```

**windows:**

```cmd
Roblox-Studio-Patcher-windows.exe
```

just run it, no install needed. finds your Studio install under `%LOCALAPPDATA%\Roblox\Versions` on its own, or pass `--binary path\to\RobloxStudioBeta.exe`.

A backup of the original binary is made before every patch (next to the original, `.bak-<timestamp>` on mac / same idea on windows).

## Custom themes

The default run asks if you want this too, or just run it standalone with `--themes`.

redirects studio's theme jsons to a folder on disk instead of loading them baked into the binary (`/Users/Shared/rbx-theme-set/` on mac, `C:\Users\Public\rbxthemeset` on windows), so you can just edit em and relaunch. grabs the stock jsons for you on first run so you've got something to start from.

edit `FoundationDarkTheme.json` and `FoundationLightTheme.json` in that folder, whichever one studio's actually using, then just relaunch studio to see it

## Building from source

```bash
cargo build --release
./target/release/studio-patcher
```

for a windows build from mac/linux you need the target + mingw (`rustup target add x86_64-pc-windows-gnu`, `brew install mingw-w64`), then `cargo build --release --target x86_64-pc-windows-gnu`.

## Issues

DM [uwufuzzywiiiaisdd](https://discord.com/users/1382448091445203037) on Discord for any issues.
