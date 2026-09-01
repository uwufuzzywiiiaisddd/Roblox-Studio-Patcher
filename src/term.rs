use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
            return false;
        }
        #[cfg(windows)]
        {
            return enable_vt();
        }
        #[cfg(not(windows))]
        true
    })
}

#[cfg(windows)]
fn enable_vt() -> bool {
    unsafe extern "system" {
        fn GetStdHandle(nstdhandle: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(handle: *mut core::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut core::ffi::c_void, mode: u32) -> i32;
    }
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

fn paint(code: &str, text: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn bold(text: &str) -> String {
    paint("1", text)
}
pub fn dim(text: &str) -> String {
    paint("2", text)
}
pub fn red(text: &str) -> String {
    paint("31", text)
}
pub fn green(text: &str) -> String {
    paint("32", text)
}
pub fn yellow(text: &str) -> String {
    paint("33", text)
}
pub fn cyan(text: &str) -> String {
    paint("36", text)
}
pub fn magenta(text: &str) -> String {
    paint("1;35", text)
}

#[cfg(windows)]
mod glyph {
    pub const SEP: &str = " - ";
    pub const STEP: &str = ">";
    pub const OK: &str = "+";
    pub const WARN: &str = "!";
    pub const RULE: &str = "-";
}
#[cfg(not(windows))]
mod glyph {
    pub const SEP: &str = " · ";
    pub const STEP: &str = "›";
    pub const OK: &str = "✓";
    pub const WARN: &str = "!";
    pub const RULE: &str = "─";
}

/// A dim horizontal rule of the given width.
pub fn rule(width: usize) -> String {
    dim(&glyph::RULE.repeat(width))
}

/// The startup wordmark, drawn in with a sweeping glint when on a terminal.
pub fn banner() {
    let version = env!("CARGO_PKG_VERSION");
    let subtitle = format!(
        "studio internal-mode{sep}themes{sep}native hooks{sep}mac + windows + linux",
        sep = glyph::SEP
    );
    println!();
    reveal_wordmark("studio-patcher");
    println!(" {}", dim(&format!("v{version}")));
    println!("  {} {}", dim("by"), cyan("Adrian (uwufuzzywiiiaisdd)"));
    println!("  {}", rule(52));
    println!("  {}", dim(&subtitle));
    println!();
}

fn reveal_wordmark(word: &str) {
    if !enabled() {
        print!("  {}", magenta(word));
        return;
    }
    let chars: Vec<char> = word.chars().collect();
    let mut out = std::io::stdout();
    for pass in 0..=chars.len() + 2 {
        let mut line = String::from("\r  ");
        for (index, glyph) in chars.iter().enumerate() {
            let distance = pass as isize - index as isize;
            let code = if distance == 0 {
                "1;97"
            } else if distance.abs() == 1 {
                "1;95"
            } else {
                "1;35"
            };
            line.push_str(&format!("\x1b[{code}m{glyph}\x1b[0m"));
        }
        let _ = write!(out, "{line}");
        let _ = out.flush();
        thread::sleep(Duration::from_millis(24));
    }
    print!("\r  {}", magenta(word));
}

/// A section header line: a leading gap, an accent arrow, and the description.
pub fn step(description: &str) {
    println!();
    println!("  {} {}", magenta(glyph::STEP), bold(description));
}

/// A dim explanation line nested under a step header.
pub fn detail(text: &str) {
    println!("    {}", dim(text));
}

/// A nested success line.
pub fn ok(message: &str) {
    println!("    {} {}", green(glyph::OK), message);
}

/// A nested soft-failure line (kept non-fatal in the flow).
pub fn warn(message: &str) {
    println!("    {} {}", yellow(glyph::WARN), dim(message));
}

#[cfg(windows)]
const SPIN_FRAMES: &[&str] = &["|", "/", "-", "\\"];
#[cfg(not(windows))]
const SPIN_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Spinner {
    pub fn start(message: &str) -> Spinner {
        if !enabled() {
            return Spinner { stop: Arc::new(AtomicBool::new(true)), handle: None };
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let message = message.to_owned();
        let handle = thread::spawn(move || {
            let mut frame = 0usize;
            let mut out = std::io::stdout();
            while !flag.load(Ordering::Relaxed) {
                let _ = write!(
                    out,
                    "\r  \x1b[1;35m{}\x1b[0m {}",
                    SPIN_FRAMES[frame % SPIN_FRAMES.len()],
                    dim(&message)
                );
                let _ = out.flush();
                frame += 1;
                thread::sleep(Duration::from_millis(80));
            }
        });
        Spinner { stop, handle: Some(handle) }
    }

    fn settle(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
            print!("\r\x1b[2K");
            let _ = std::io::stdout().flush();
        }
    }

    pub fn finish(mut self) {
        self.settle();
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.settle();
    }
}
