use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
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
    let mut out = vec![];
    for tok in s.split_whitespace() {
        if tok == "??" || tok == "?" {
            if !allow_wild {
                bail!("no wildcards in --patch, every byte needs a value");
            }
            out.push(PatByte::Wild);
        } else {
            out.push(PatByte::Exact(u8::from_str_radix(tok, 16).with_context(|| tok.to_string())?));
        }
    }
    Ok(out)
}

fn find_matches(haystack: &[u8], pattern: &[PatByte]) -> Vec<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return vec![];
    }
    let mut hits = vec![];
    for start in 0..=(haystack.len() - pattern.len()) {
        let ok = pattern.iter().enumerate().all(|(i, p)| match p {
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
    for c in ["/Applications/RobloxStudio.app", "/Applications/Roblox Studio.app"] {
        if PathBuf::from(c).exists() {
            return Ok(PathBuf::from(c));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join("Applications/RobloxStudio.app");
        if p.exists() {
            return Ok(p);
        }
    }
    let out = Command::new("mdfind")
        .arg("kMDItemCFBundleIdentifier == 'com.roblox.RobloxStudioBrowser'")
        .output()?;
    let found = String::from_utf8_lossy(&out.stdout);
    let first = found.lines().next().filter(|s| !s.is_empty());
    first.map(PathBuf::from).context("couldn't find RobloxStudio.app, pass --binary")
}

fn resolve_macho(path: &Path) -> Result<PathBuf> {
    if path.extension().and_then(|e| e.to_str()) != Some("app") {
        return Ok(path.to_path_buf());
    }
    // can't just grab the first entry, gotta read the actual bundle exec name
    let plist = path.join("Contents/Info.plist");
    let out = Command::new("defaults")
        .args(["read", &plist.to_string_lossy(), "CFBundleExecutable"])
        .output()?;
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() {
        bail!("no CFBundleExecutable in {}", plist.display());
    }
    Ok(path.join("Contents/MacOS").join(name))
}

fn app_root(macho_path: &Path) -> Option<PathBuf> {
    macho_path.ancestors().find(|p| p.extension().and_then(|e| e.to_str()) == Some("app")).map(Into::into)
}

fn backup(macho_path: &Path) -> Result<()> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let bak = macho_path.with_extension(format!("bak-{ts}"));
    fs::copy(macho_path, &bak)?;
    println!("backup: {}", bak.display());
    Ok(())
}

fn resign(macho_path: &Path) -> Result<()> {
    let target = app_root(macho_path).unwrap_or_else(|| macho_path.to_path_buf());
    println!("codesigning {} (adhoc)", target.display());
    let ok = Command::new("codesign").args(["--force", "--deep", "--sign", "-"]).arg(&target).status()?.success();
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
    let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let mut off = 32usize;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let sz = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == 0x19 && &data[off + 8..off + 14] == b"__TEXT" {
            let vmaddr = u64::from_le_bytes(data[off + 24..off + 32].try_into().unwrap());
            let vmsize = u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap());
            let fileoff = u64::from_le_bytes(data[off + 40..off + 48].try_into().unwrap());
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
    let rd = (word & 0x1F) as u8;
    let lo = ((word >> 29) & 0x3) as i64;
    let hi = ((word >> 5) & 0x7FFFF) as i64;
    let mut imm = (hi << 2) | lo;
    if imm & (1 << 20) != 0 {
        imm -= 1 << 21;
    }
    Some((rd, ((pc as i64 & !0xFFF) + (imm << 12)) as u64))
}

fn ldrb(word: u32) -> Option<(u8, u8, u32)> {
    (word & 0xFFC00000 == 0x39400000).then(|| {
        ((word & 0x1F) as u8, ((word >> 5) & 0x1F) as u8, (word >> 10) & 0xFFF)
    })
}

fn mov_imm1(rd: u8) -> [u8; 4] {
    // movz wD, #1 - 4 bytes, same length as the ldrb it's stomping
    (0x52800020u32 | rd as u32).to_le_bytes()
}

fn scan_globals(data: &[u8], globals: &[u64]) -> Result<Vec<(usize, [u8; 4])>> {
    let (vmaddr, fileoff, vmsize) = text_bounds(data)?;
    let slide = vmaddr as i64 - fileoff as i64;
    let (start, end) = (fileoff as usize, ((fileoff + vmsize) as usize).min(data.len()));

    let mut out = vec![];
    let mut i = start;
    while i + 8 <= end {
        let w1 = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        if let Some((rd, page)) = adrp(w1, (i as i64 + slide) as u64) {
            let w2 = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap());
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

fn run_globals(macho_path: &Path, args: &Args) -> Result<()> {
    let globals = args
        .globals
        .iter()
        .map(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).with_context(|| s.clone()))
        .collect::<Result<Vec<_>>>()?;

    let mut data = fs::read(macho_path)?;
    let patches = scan_globals(&data, &globals)?;
    if patches.is_empty() {
        bail!("nothing found for {globals:x?}, wrong version or already patched");
    }
    println!("{} sites:", patches.len());
    for (off, new) in &patches {
        println!("  0x{off:x} -> {}", new.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "));
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
    let sig = parse_pattern(args.signature.as_deref().unwrap(), true)?;
    let patch = parse_pattern(args.patch.as_deref().unwrap(), false)?;
    if sig.len() != patch.len() {
        bail!("sig is {} bytes, patch is {}, gotta match", sig.len(), patch.len());
    }

    let mut data = fs::read(macho_path)?;
    let hits = find_matches(&data, &sig);
    match hits.len() {
        0 => bail!("signature not found - wrong binary/version?"),
        1 => println!("1 match @ 0x{:x}", hits[0]),
        n => {
            println!("{n} matches:");
            for (i, off) in hits.iter().enumerate() {
                println!("  [{i}] 0x{off:x}");
            }
            if args.occurrence >= n {
                bail!("--occurrence {} out of range ({n} matches)", args.occurrence);
            }
        }
    }

    let offset = hits[args.occurrence];
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

fn main() -> Result<()> {
    let args = Args::parse();
    let target = args.binary.clone().map(Ok).unwrap_or_else(discover_binary)?;
    let macho_path = resolve_macho(&target)?;
    println!("target: {}", macho_path.display());

    if !args.globals.is_empty() {
        run_globals(&macho_path, &args)
    } else if args.signature.is_some() && args.patch.is_some() {
        run_sig(&macho_path, &args)
    } else {
        bail!("need --signature/--patch or --globals")
    }
}
