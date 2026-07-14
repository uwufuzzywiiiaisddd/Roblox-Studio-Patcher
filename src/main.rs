use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "studio-patcher", version)]
struct Args {
    #[arg(long)]
    binary: Option<PathBuf>,

    #[arg(long)]
    signature: Option<String>,

    #[arg(long)]
    patch: Option<String>,

    #[arg(long, default_value_t = 0)]
    occurrence: usize,

    // hex addrs, comma sep. every adrp+ldrb reading one of these becomes mov wD,#1
    #[arg(long, value_delimiter = ',')]
    globals: Vec<String>,

    #[arg(long)]
    themes: bool,

    #[arg(long)]
    discover: bool,

    #[arg(long)]
    dry_run: bool,

    #[arg(long)]
    no_backup: bool,

    #[arg(long)]
    no_resign: bool,
}

enum PatByte {
    Exact(u8),
    Wild,
}

fn parse_pattern(s: &str, allow_wild: bool) -> Result<Vec<PatByte>> {
    let mut out: Vec<PatByte> = vec![];
    for tok in s.split_whitespace() {
        if tok == "??" || tok == "?" {
            if !allow_wild {
                bail!("no wildcards in --patch, every byte needs a value");
            }
            out.push(PatByte::Wild);
        } else {
            out.push(PatByte::Exact(
                u8::from_str_radix(tok, 16).with_context(|| tok.to_string())?,
            ));
        }
    }
    Ok(out)
}

fn find_matches(haystack: &[u8], pattern: &[PatByte]) -> Vec<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return vec![];
    }
    let mut hits: Vec<usize> = vec![];
    for start in 0..=(haystack.len() - pattern.len()) {
        let ok: bool = pattern.iter().enumerate().all(|(i, p)| match p {
            PatByte::Wild => true,
            PatByte::Exact(b) => haystack[start + i] == *b,
        });
        if ok {
            hits.push(start);
        }
    }
    hits
}

fn discover_binary() -> Result<PathBuf> {
    for c in [
        "/Applications/RobloxStudio.app",
        "/Applications/Roblox Studio.app",
    ] {
        if PathBuf::from(c).exists() {
            return Ok(PathBuf::from(c));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p: PathBuf = PathBuf::from(home).join("Applications/RobloxStudio.app");
        if p.exists() {
            return Ok(p);
        }
    }
    let out: std::process::Output = Command::new("mdfind")
        .arg("kMDItemCFBundleIdentifier == 'com.roblox.RobloxStudioBrowser'")
        .output()?;
    let found: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    let first: Option<&str> = found.lines().next().filter(|s: &&str| !s.is_empty());
    first
        .map(PathBuf::from)
        .context("couldn't find RobloxStudio.app, pass --binary")
}

fn resolve_macho(path: &Path) -> Result<PathBuf> {
    if path.extension().and_then(|e| e.to_str()) != Some("app") {
        return Ok(path.to_path_buf());
    }
    // can't just grab the first entry, gotta read the actual bundle exec name
    let plist = path.join("Contents/Info.plist");
    let out: std::process::Output = Command::new("defaults")
        .args(["read", &plist.to_string_lossy(), "CFBundleExecutable"])
        .output()?;
    let name: String = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() {
        bail!("no CFBundleExecutable in {}", plist.display());
    }
    Ok(path.join("Contents/MacOS").join(name))
}

fn app_root(macho_path: &Path) -> Option<PathBuf> {
    macho_path
        .ancestors()
        .find(|p: &&Path| p.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) == Some("app"))
        .map(Into::into)
}

fn backup(macho_path: &Path) -> Result<()> {
    let ts: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bak: PathBuf = macho_path.with_extension(format!("bak-{ts}"));
    fs::copy(macho_path, &bak)?;
    println!("backup: {}", bak.display());
    Ok(())
}

fn resign(macho_path: &Path) -> Result<()> {
    let target: PathBuf = app_root(macho_path).unwrap_or_else(|| macho_path.to_path_buf());
    println!("codesigning {} (adhoc)", target.display());
    let ok: bool = Command::new("codesign")
        .args(["--force", "--deep", "--sign", "-"])
        .arg(&target)
        .status()?
        .success();
    if !ok {
        bail!("codesign failed - binary is patched but won't launch till you resign it");
    }
    Ok(())
}

// va - (vmaddr - fileoff) as long as it's inside the segment
fn text_bounds(data: &[u8]) -> Result<(u64, u64, u64)> {
    if data.len() < 32 || data[0..4] != [0xcf, 0xfa, 0xed, 0xfe] {
        bail!("bad macho magic, not arm64/x64 little endian?");
    }
    let ncmds: u32 = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let mut off: usize = 32usize;
    for _ in 0..ncmds {
        let cmd: u32 = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let sz: usize = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == 0x19 && &data[off + 8..off + 14] == b"__TEXT" {
            let vmaddr: u64 = u64::from_le_bytes(data[off + 24..off + 32].try_into().unwrap());
            let vmsize: u64 = u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap());
            let fileoff: u64 = u64::from_le_bytes(data[off + 40..off + 48].try_into().unwrap());
            return Ok((vmaddr, fileoff, vmsize));
        }
        off += sz;
    }
    bail!("no __TEXT segment??")
}

fn adrp(word: u32, pc: u64) -> Option<(u8, u64)> {
    if word & 0x9F000000 != 0x90000000 {
        return None;
    }
    let rd: u8 = (word & 0x1F) as u8;
    let lo: i64 = ((word >> 29) & 0x3) as i64;
    let hi: i64 = ((word >> 5) & 0x7FFFF) as i64;
    let mut imm: i64 = (hi << 2) | lo;
    if imm & (1 << 20) != 0 {
        imm -= 1 << 21;
    }
    Some((rd, ((pc as i64 & !0xFFF) + (imm << 12)) as u64))
}

fn add_imm(word: u32) -> Option<(u8, u8, u32)> {
    (word & 0x7FC00000 == 0x11000000).then(|| {
        (
            (word & 0x1F) as u8,
            ((word >> 5) & 0x1F) as u8,
            (word >> 10) & 0xFFF,
        )
    })
}

fn text_section_bounds(data: &[u8]) -> Result<(u64, u64)> {
    let ncmds: u32 = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let mut off: usize = 32usize;
    for _ in 0..ncmds {
        let cmd: u32 = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let sz: usize = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == 0x19 && &data[off + 8..off + 14] == b"__TEXT" {
            let nsects: u32 = u32::from_le_bytes(data[off + 48..off + 52].try_into().unwrap());
            let mut sect_off: usize = off + 72;
            for _ in 0..nsects {
                if &data[sect_off..sect_off + 6] == b"__text" {
                    let addr: u64 =
                        u64::from_le_bytes(data[sect_off + 32..sect_off + 40].try_into().unwrap());
                    let size: u64 =
                        u64::from_le_bytes(data[sect_off + 40..sect_off + 48].try_into().unwrap());
                    return Ok((addr, addr + size));
                }
                sect_off += 80;
            }
        }
        off += sz;
    }
    bail!("no __text section??")
}

fn b_target(word: u32, pc: u64) -> Option<u64> {
    if word & 0xFC000000 != 0x14000000 {
        return None;
    }
    let mut imm: i64 = (word & 0x03FFFFFF) as i64;
    if imm & (1 << 25) != 0 {
        imm -= 1 << 26;
    }
    Some((pc as i64 + imm * 4) as u64)
}

fn and_ldrb_globals(data: &[u8], slide: i64, fstart: usize, fend: usize) -> Vec<u64> {
    let mut has_and: bool = false;
    let mut addrs: Vec<u64> = vec![];
    let mut i: usize = fstart;
    while i + 8 <= fend {
        let w1: u32 = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        if is_and(w1) {
            has_and = true;
        }
        if let Some((rd, page)) = adrp(w1, (i as i64 + slide) as u64) {
            let w2: u32 = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap());
            if let Some((_rt, rn, imm12)) = ldrb(w2) {
                if rn == rd {
                    addrs.push(page + imm12 as u64);
                }
            }
        }
        i += 4;
    }
    if has_and {
        addrs
    } else {
        vec![]
    }
}

fn discover_via_anchor(data: &[u8], anchor: &str) -> Result<Vec<u64>> {
    let (vmaddr, fileoff, vmsize) = text_bounds(data)?;
    let slide: i64 = vmaddr as i64 - fileoff as i64;
    let (text_lo, text_hi): (u64, u64) = text_section_bounds(data)?;

    let needle: Vec<u8> = anchor.bytes().collect();
    let pattern: Vec<PatByte> = needle.iter().map(|b: &u8| PatByte::Exact(*b)).collect();
    let str_offsets: Vec<usize> = find_matches(data, &pattern);
    if str_offsets.is_empty() {
        bail!("anchor string {anchor:?} not found in binary");
    }

    let (text_lo_off, text_hi_off): (usize, usize) = (
        ((text_lo as i64) - slide) as usize,
        ((text_hi as i64) - slide) as usize,
    );
    let mut starts: Vec<usize> = function_starts(data)?
        .into_iter()
        .map(|a: u64| ((a as i64) - slide) as usize)
        .filter(|&o: &usize| o >= text_lo_off && o < text_hi_off)
        .collect();
    starts.sort_unstable();
    starts.dedup();

    let (scan_start, scan_end) = (
        fileoff as usize,
        ((fileoff + vmsize) as usize).min(data.len()),
    );

    for &str_off in &str_offsets {
        let str_addr: u64 = (str_off as i64 + slide) as u64;

        let mut ref_sites: Vec<usize> = vec![];
        let mut i: usize = scan_start;
        while i + 8 <= scan_end {
            let w1: u32 = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            if let Some((rd, page)) = adrp(w1, (i as i64 + slide) as u64) {
                let w2: u32 = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap());
                if let Some((_rd2, rn, imm12)) = add_imm(w2) {
                    if rn == rd && page + imm12 as u64 == str_addr {
                        ref_sites.push(i);
                    }
                }
            }
            i += 4;
        }

        for &site in &ref_sites {
            let win_start: usize = site.saturating_sub(160);
            let win_end: usize = (site + 160).min(scan_end);
            let mut j: usize = win_start;
            while j + 8 <= win_end {
                let w1: u32 = u32::from_le_bytes(data[j..j + 4].try_into().unwrap());
                if let Some((rd, page)) = adrp(w1, (j as i64 + slide) as u64) {
                    let w2: u32 = u32::from_le_bytes(data[j + 4..j + 8].try_into().unwrap());
                    if let Some((_rd2, rn, imm12)) = add_imm(w2) {
                        if rn == rd {
                            let candidate: u64 = page + imm12 as u64;
                            if candidate >= text_lo && candidate < text_hi {
                                let mut cand_off: usize = ((candidate as i64) - slide) as usize;
                                for _hop in 0..4 {
                                    let Some(&fend) = starts.iter().find(|&&s| s > cand_off) else {
                                        break;
                                    };
                                    let bound: usize = fend.min(cand_off + 256);
                                    if bound - cand_off <= 8 {
                                        let w: u32 = u32::from_le_bytes(
                                            data[cand_off..cand_off + 4].try_into().unwrap(),
                                        );
                                        if let Some(t) =
                                            b_target(w, (cand_off as i64 + slide) as u64)
                                        {
                                            if t >= text_lo && t < text_hi {
                                                cand_off = ((t as i64) - slide) as usize;
                                                continue;
                                            }
                                        }
                                        break;
                                    }
                                    let addrs: Vec<u64> =
                                        and_ldrb_globals(data, slide, cand_off, bound);
                                    if !addrs.is_empty() {
                                        return Ok(addrs);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                j += 4;
            }
        }
    }
    bail!("found the anchor string but couldn't trace a getter function near it - roblox may have changed this pattern")
}

fn ldrb(word: u32) -> Option<(u8, u8, u32)> {
    (word & 0xFFC00000 == 0x39400000).then(|| {
        (
            (word & 0x1F) as u8,
            ((word >> 5) & 0x1F) as u8,
            (word >> 10) & 0xFFF,
        )
    })
}

fn mov_imm1(rd: u8) -> [u8; 4] {
    // movz wD, #1 - 4 bytes, same length as the ldrb it's stomping
    (0x52800020u32 | rd as u32).to_le_bytes()
}

fn is_and(word: u32) -> bool {
    let and_reg: bool = word & 0x7F200000 == 0x0A000000;
    let and_imm32: bool = word & 0xFF800000 == 0x12000000;
    let and_imm64: bool = word & 0xFF800000 == 0x92000000;
    and_reg || and_imm32 || and_imm64
}

fn uleb128(bytes: &[u8], i: &mut usize) -> u64 {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte: u8 = bytes[*i];
        *i += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    result
}

fn function_starts(data: &[u8]) -> Result<Vec<u64>> {
    let (vmaddr, ..) = text_bounds(data)?;
    let ncmds: u32 = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let mut off: usize = 32usize;
    for _ in 0..ncmds {
        let cmd: u32 = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let sz: usize = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == 0x26 {
            let dataoff: usize =
                u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()) as usize;
            let datasize: usize =
                u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap()) as usize;
            let bytes: &[u8] = &data[dataoff..dataoff + datasize];
            let mut addrs: Vec<u64> = vec![];
            let mut addr: u64 = vmaddr;
            let mut i: usize = 0;
            while i < bytes.len() {
                let delta: u64 = uleb128(bytes, &mut i);
                if delta == 0 {
                    break;
                }
                addr += delta;
                addrs.push(addr);
            }
            return Ok(addrs);
        }
        off += sz;
    }
    bail!("no LC_FUNCTION_STARTS - can't auto-discover without it, pass --globals manually")
}

fn scan_globals(data: &[u8], globals: &[u64]) -> Result<Vec<(usize, [u8; 4])>> {
    let (vmaddr, fileoff, vmsize) = text_bounds(data)?;
    let slide: i64 = vmaddr as i64 - fileoff as i64;
    let (start, end) = (
        fileoff as usize,
        ((fileoff + vmsize) as usize).min(data.len()),
    );

    let mut out: Vec<(usize, [u8; 4])> = vec![];
    let mut i: usize = start;
    while i + 8 <= end {
        let w1: u32 = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        if let Some((rd, page)) = adrp(w1, (i as i64 + slide) as u64) {
            let w2: u32 = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap());
            if let Some((rt, rn, imm12)) = ldrb(w2) {
                if rn == rd && globals.contains(&(page + imm12 as u64)) {
                    out.push((i + 4, mov_imm1(rt)));
                }
            }
        }
        i += 4;
    }
    Ok(out)
}

fn run_discover(macho_path: &Path) -> Result<()> {
    let data: Vec<u8> = fs::read(macho_path)?;
    let addrs: Vec<u64> = discover_via_anchor(&data, "HasInternalPermission")?;
    println!(
        "found it via the HasInternalPermission getter, {} global(s):",
        addrs.len()
    );
    for a in &addrs {
        println!("  0x{a:x}");
    }
    println!(
        "--globals {}",
        addrs
            .iter()
            .map(|a: &u64| format!("0x{a:x}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(())
}

fn run_globals(macho_path: &Path, args: &Args) -> Result<()> {
    let mut data: Vec<u8> = fs::read(macho_path)?;

    let globals: Vec<u64> = if args.globals.len() == 1 && args.globals[0] == "auto" {
        let found: Vec<u64> = discover_via_anchor(&data, "HasInternalPermission")?;
        println!("auto-discovered {} global(s): {:x?}", found.len(), found);
        found
    } else {
        args.globals
            .iter()
            .map(|s: &String| {
                u64::from_str_radix(s.trim().trim_start_matches("0x"), 16)
                    .with_context(|| s.clone())
            })
            .collect::<Result<Vec<_>>>()?
    };

    let patches: Vec<(usize, [u8; 4])> = scan_globals(&data, &globals)?;
    if patches.is_empty() {
        bail!("nothing found for {globals:x?}, wrong version or already patched");
    }
    println!("{} sites:", patches.len());
    for (off, new) in &patches {
        println!(
            "  0x{off:x} -> {}",
            new.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    if args.dry_run {
        println!("dry run");
        return Ok(());
    }
    if !args.no_backup {
        backup(macho_path)?;
    }
    for (off, new) in &patches {
        data[*off..*off + 4].copy_from_slice(new);
    }
    fs::write(macho_path, &data)?;
    println!("patched {}", patches.len());
    if !args.no_resign {
        resign(macho_path)?;
    }
    Ok(())
}

fn run_sig(macho_path: &Path, args: &Args) -> Result<()> {
    let sig: Vec<PatByte> = parse_pattern(args.signature.as_deref().unwrap(), true)?;
    let patch: Vec<PatByte> = parse_pattern(args.patch.as_deref().unwrap(), false)?;
    if sig.len() != patch.len() {
        bail!(
            "sig is {} bytes, patch is {}, gotta match",
            sig.len(),
            patch.len()
        );
    }

    let mut data: Vec<u8> = fs::read(macho_path)?;
    let hits: Vec<usize> = find_matches(&data, &sig);
    match hits.len() {
        0 => bail!("signature not found - wrong binary/version?"),
        1 => println!("1 match @ 0x{:x}", hits[0]),
        n => {
            println!("{n} matches:");
            for (i, off) in hits.iter().enumerate() {
                println!("  [{i}] 0x{off:x}");
            }
            if args.occurrence >= n {
                bail!(
                    "--occurrence {} out of range ({n} matches)",
                    args.occurrence
                );
            }
        }
    }

    let offset: usize = hits[args.occurrence];
    if args.dry_run {
        println!("dry run");
        return Ok(());
    }
    if !args.no_backup {
        backup(macho_path)?;
    }
    for (i, p) in patch.iter().enumerate() {
        if let PatByte::Exact(b) = p {
            data[offset + i] = *b;
        }
    }
    fs::write(macho_path, &data)?;
    println!("patched {} bytes @ 0x{:x}", patch.len(), offset);
    if !args.no_resign {
        resign(macho_path)?;
    }
    Ok(())
}

fn run_themes(macho_path: &Path, args: &Args) -> Result<()> {
    // absolute path so we dont have to rename the bin xddd
    let themes_dir: &str = "/Users/Shared/rbx-theme-set"; // must stay exactly 26 chars, see below
    let dark_new: String = format!("{themes_dir}/FoundationDarkTheme.json");
    let light_new: String = format!("{themes_dir}/FoundationLightTheme.json");
    let swaps: [(&str, &str); 2] = [
        (
            ":/Platform/Base/QtUI/themes/FoundationDarkTheme.json",
            dark_new.as_str(),
        ),
        (
            ":/Platform/Base/QtUI/themes/FoundationLightTheme.json",
            light_new.as_str(),
        ),
    ];
    for (old, new) in swaps {
        if old.len() != new.len() {
            bail!(
                "bug: {old:?} is {} bytes, {new:?} is {} bytes",
                old.len(),
                new.len()
            );
        }
    }

    let mut data: Vec<u8> = fs::read(macho_path)?;
    let mut sites: Vec<(usize, &str)> = vec![];
    for (old, new) in swaps {
        let pattern: Vec<PatByte> = old.bytes().map(PatByte::Exact).collect();
        for off in find_matches(&data, &pattern) {
            sites.push((off, new));
        }
    }
    if sites.is_empty() {
        bail!("no embedded theme paths found - wrong build, already patched, or qt stopped doing it this way");
    }
    println!("{} theme path(s) found", sites.len());

    if args.dry_run {
        println!("dry run");
        return Ok(());
    }
    if !args.no_backup {
        backup(macho_path)?;
    }
    for (off, new) in &sites {
        data[*off..*off + new.len()].copy_from_slice(new.as_bytes());
    }
    fs::write(macho_path, &data)?;
    println!("redirected {} theme path(s) to {themes_dir}", sites.len());

    fs::create_dir_all(themes_dir)?;
    for name in ["FoundationDarkTheme.json", "FoundationLightTheme.json"] {
        let dest: PathBuf = Path::new(themes_dir).join(name);
        if dest.exists() {
            continue;
        }
        let url: String = format!(
            "https://raw.githubusercontent.com/MaximumADHD/Roblox-Client-Tracker/roblox/QtResources/Platform/Base/QtUI/themes/{name}"
        );
        let ok: bool = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&dest)
            .arg(&url)
            .status()?
            .success();
        if !ok {
            bail!("couldn't grab {name}, drop your own copy in {themes_dir}");
        }
    }
    println!("edit the jsons in {themes_dir} then relaunch studio");

    let domain: &str = "com.roblox.RobloxStudio";
    let key: &str = "Themes.CurrentTheme";
    let current: String = Command::new("defaults")
        .args(["read", domain, key])
        .output()
        .map(|o: std::process::Output| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if current != "Dark" && current != "Light" {
        Command::new("defaults")
            .args(["write", domain, key, "-string", "Dark"])
            .status()?;
        println!("{domain} {key} was {current:?}, doesn't match a real theme name - reset to \"Dark\" so studio doesn't crash looking it up");
    }

    if !args.no_resign {
        resign(macho_path)?;
    }
    Ok(())
}

fn ask_yn(q: &str) -> bool {
    print!("{q} [y/N] ");
    let _ = io::stdout().flush();
    let mut line: String = String::new();
    io::stdin().read_line(&mut line).ok();
    matches!(line.trim(), "y" | "Y" | "yes")
}

fn run_auto(macho_path: &Path, args: &Args) -> Result<()> {
    let mut globals_args: Args = args.clone();
    globals_args.globals = vec!["auto".to_string()];
    if let Err(e) = run_globals(macho_path, &globals_args) {
        println!("permission patch failed ({e}) - probably already patched");
    }

    println!("custom themes work by patching the binary to load theme jsons off disk");
    if ask_yn("enable custom theme support?") {
        run_themes(macho_path, args)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Args = Args::parse();
    let target: PathBuf = args
        .binary
        .clone()
        .map(Ok)
        .unwrap_or_else(discover_binary)?;
    let macho_path: PathBuf = resolve_macho(&target)?;
    println!("target: {}", macho_path.display());

    let mut did_something: bool = false;
    if args.discover {
        run_discover(&macho_path)?;
        did_something = true;
    }
    if !args.globals.is_empty() {
        run_globals(&macho_path, &args)?;
        did_something = true;
    }
    if args.signature.is_some() && args.patch.is_some() {
        run_sig(&macho_path, &args)?;
        did_something = true;
    }
    if args.themes {
        run_themes(&macho_path, &args)?;
        did_something = true;
    }
    if !did_something {
        run_auto(&macho_path, &args)?;
    }
    Ok(())
}
