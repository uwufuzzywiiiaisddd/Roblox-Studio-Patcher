# studio-internal-patcher

Patches RobloxStudio.app so `HasInternalPermission` always returns true.

## What this actually does

Studio has a hidden internal mode normally reserved for Roblox employees and their "Soothsayer" testers - it unlocks debug tools, experimental features, and internal-only APIs/menus regular developers don't get. `HasInternalPermission` is the check that gates it; this patches it open for everyone.

Related: the command bar's script identity system has an `ElevatedStudioPlugin` identity level alongside the normal ones (`CommandBar`, etc.) - same general concept of elevated/internal access, just a separate mechanism from the permission check this tool patches.

## Usage

```bash
./auto_patch.sh                          # patches /Applications/RobloxStudio.app
./auto_patch.sh /path/to/RobloxStudio.app # or a custom path
```

Requires macOS + arm64 Studio. It'll install Homebrew and Rust itself if you don't have them.

If your exact build isn't supported yet, it'll tell you which ones are and offer to force-patch with the latest anyway (safe - it just fails cleanly if the addresses don't match).

A backup of the original binary is made before every patch (`RobloxStudio.bak-<timestamp>`, next to the original).

mac/arm only rn cuz i wanted to learn arm. ill probably get around to a windows x86 version eventually if [7ap's patcher](https://github.com/7ap/internal-studio-patcher) remains archived, ngl arm is kinda mid tho

probably gonna add custom theme support at some point too, no eta tho

## Issues

DM [uwufuzzywiiiaisdd](https://discord.com/users/1382448091445203037) on Discord for any issues.
