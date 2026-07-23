//! fossroot-agent — the native-messaging host that bridges the Fossroot browser
//! extension to the local machine.
//!
//! Run with no subcommand, it speaks Chrome/Edge native messaging on stdin/stdout
//! (this is how the browser launches it). `register` / `unregister` manage the
//! host manifest and per-browser pointers so the extension can find it.

mod protocol;
mod register;
mod rpc;

use std::io::{self, Write};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "fossroot-agent",
    version,
    about = "Fossroot native-messaging host"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Register this host with Chrome and Edge (writes the manifest + pointer)
    Register {
        /// Extension ID permitted to connect (defaults to the built-in key)
        #[arg(long, default_value = register::DEFAULT_EXTENSION_ID)]
        extension_id: String,
    },
    /// Remove the host registration from Chrome and Edge
    Unregister,
}

fn main() {
    match Args::parse().command {
        Some(Command::Register { extension_id }) => match register::register(&extension_id) {
            Ok(summary) => println!("{summary}"),
            Err(e) => {
                eprintln!("register failed: {e}");
                std::process::exit(1);
            }
        },
        Some(Command::Unregister) => match register::unregister() {
            Ok(summary) => println!("{summary}"),
            Err(e) => {
                eprintln!("unregister failed: {e}");
                std::process::exit(1);
            }
        },
        None => serve(),
    }
}

/// The native-messaging loop: read framed requests until the browser closes the
/// port, answering each. Malformed requests get an error response rather than a
/// crash, so one bad message never tears down the port.
fn serve() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let raw = match protocol::read_message(&mut reader) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break, // browser closed the port
            Err(_) => break,   // framing error — end the conversation
        };
        let response = match serde_json::from_slice::<rpc::Request>(&raw) {
            Ok(req) => rpc::handle(req),
            Err(e) => rpc::Response::Err {
                ok: false,
                error: format!("bad request: {e}"),
            },
        };
        let payload = serde_json::to_vec(&response)
            .unwrap_or_else(|_| br#"{"ok":false,"error":"failed to serialize response"}"#.to_vec());
        if protocol::write_message(&mut writer, &payload).is_err() {
            break;
        }
    }
    let _ = writer.flush();
}
