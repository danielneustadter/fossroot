//! fossroot — open-source manager for DoD PKI CA certificate trust stores.
//!
//! One binary, two faces: `fossroot <subcommand>` is a CLI; double-clicking
//! (no arguments) opens the GUI. Release builds use the Windows GUI subsystem
//! so no console window flashes; CLI mode re-attaches to the parent console.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod cli;
mod gui;

fn main() {
    if std::env::args().len() <= 1 {
        if let Err(err) = gui::run() {
            // No console in GUI mode; surface fatal launch errors via stderr
            // anyway (visible when started from a terminal).
            attach_parent_console();
            eprintln!("error: {err}");
            std::process::exit(1);
        }
        return;
    }
    attach_parent_console();
    if let Err(err) = cli::run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// In release builds the exe uses the GUI subsystem, so CLI invocations must
/// attach back to the console that started them for stdout/stderr to appear.
#[cfg(all(windows, not(debug_assertions)))]
fn attach_parent_console() {
    use windows::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(all(windows, not(debug_assertions))))]
fn attach_parent_console() {}
