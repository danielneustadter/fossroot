//! fossroot — open-source manager for DoD PKI CA certificate trust stores.
//!
//! With arguments: CLI. With no arguments: GUI (added in a later milestone;
//! for now, no args prints help).

mod cli;

fn main() {
    if std::env::args().len() <= 1 {
        // GUI milestone lands here; until then, show help.
        cli::run_help_banner();
        return;
    }
    if let Err(err) = cli::run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
