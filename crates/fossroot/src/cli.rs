use clap::{Parser, Subcommand};
use fossroot_core::certs::format_unix;
use fossroot_core::store::{platform, Location, StoreKind, SystemStore, TrustStore};
use fossroot_core::{diff, Bundle, CertStatus, DiffReport};

#[derive(Parser)]
#[command(
    name = "fossroot",
    version,
    about = "Open-source manager for DoD PKI CA certificate trust stores",
    after_help = "Running with no arguments launches the GUI.\n\
                  Fossroot never ships certificates: bundles are fetched from DISA's official\n\
                  distribution point and cryptographically verified against pinned DoD roots."
)]
struct Args {
    /// Which DISA bundle group to operate on: dod, eca, jitc, or wcf
    #[arg(long, global = true, default_value = "dod", value_name = "GROUP")]
    group: String,

    #[command(subcommand)]
    command: Command,
}

fn parse_group(s: &str) -> Result<fossroot_core::Group, Box<dyn std::error::Error>> {
    fossroot_core::Group::from_token(s)
        .ok_or_else(|| format!("unknown group '{s}' (expected: dod, eca, jitc, wcf)").into())
}

#[derive(Subcommand)]
enum Command {
    /// Show bundle verification and per-store install coverage (read-only)
    Status {
        /// Use a local bundle zip or .p7b instead of downloading
        #[arg(long, value_name = "FILE")]
        offline: Option<std::path::PathBuf>,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
        /// List every certificate, not just a summary
        #[arg(long, short)]
        verbose: bool,
    },
    /// Install missing bundle certificates into a trust store
    Install {
        /// Target the Local Machine stores (requires an elevated shell)
        #[arg(long)]
        machine: bool,
        #[arg(long, value_name = "FILE")]
        offline: Option<std::path::PathBuf>,
        /// Also remove stale DoD CAs no longer in the bundle
        #[arg(long)]
        prune: bool,
        /// Skip the confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
    /// Remove every bundle certificate (full uninstall of what Fossroot manages)
    Remove {
        /// Target the Local Machine stores (requires an elevated shell)
        #[arg(long)]
        machine: bool,
        #[arg(long, value_name = "FILE")]
        offline: Option<std::path::PathBuf>,
        #[arg(long, short)]
        yes: bool,
    },
    /// Export bundle certificates as individual .cer files plus a PEM chain
    Export {
        /// Output directory (created if needed)
        #[arg(long, short, value_name = "DIR", default_value = "fossroot-export")]
        out: std::path::PathBuf,
        #[arg(long, value_name = "FILE")]
        offline: Option<std::path::PathBuf>,
    },
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let group = parse_group(&args.group)?;
    match args.command {
        Command::Status {
            offline,
            json,
            verbose,
        } => status(group, offline, json, verbose),
        Command::Install {
            machine,
            offline,
            prune,
            yes,
        } => install(group, machine, offline, prune, yes),
        Command::Remove {
            machine,
            offline,
            yes,
        } => remove(group, machine, offline, yes),
        Command::Export { out, offline } => export(group, out, offline),
    }
}

fn load_bundle(
    group: fossroot_core::Group,
    offline: Option<std::path::PathBuf>,
) -> Result<Bundle, Box<dyn std::error::Error>> {
    let bundle = match offline {
        Some(path) => {
            eprintln!("Loading bundle from {} ...", path.display());
            Bundle::from_file(&path)?
        }
        None => {
            eprintln!("Fetching {} bundle from {} ...", group.name(), group.url());
            Bundle::fetch_group(group)?
        }
    };
    if bundle.group.is_test_pki() {
        eprintln!(
            "WARNING: {} is a TEST PKI. Do not install it into a production trust store.",
            bundle.group.name()
        );
    }
    Ok(bundle)
}

fn diff_location(
    bundle: &Bundle,
    location: Location,
) -> Result<DiffReport, Box<dyn std::error::Error>> {
    let store = platform();
    let in_root = store.list(SystemStore {
        location,
        kind: StoreKind::Root,
    })?;
    let in_ca = store.list(SystemStore {
        location,
        kind: StoreKind::Ca,
    })?;
    Ok(diff::diff(
        &bundle.certs,
        &in_root,
        &in_ca,
        chrono::Utc::now().timestamp(),
    ))
}

fn print_verification(bundle: &Bundle) {
    println!(
        "Bundle:    {} v{} ({} certificates)",
        bundle.group.name(),
        bundle.version,
        bundle.certs.len()
    );
    println!("Source:    {}", bundle.source);
    if !bundle.zip_sha256.is_empty() {
        println!("Zip SHA-256: {}", bundle.zip_sha256);
    }
    match (
        &bundle.verify.manifest_signed,
        &bundle.verify.manifest_signer,
    ) {
        (true, Some(signer)) => {
            println!("Manifest:  SIGNED — DoD PKE credential '{signer}', chain verified to pinned DoD root");
        }
        _ => println!("Manifest:  n/a (bare .p7b input — chain verification only)"),
    }
    // For the DoD group the roots are pinned directly; for other groups the
    // roots are anchored transitively by the DISA-signed manifest.
    let anchor_desc = if bundle.group == fossroot_core::Group::Dod {
        "pinned DoD roots"
    } else {
        "manifest-anchored roots"
    };
    println!(
        "Chains:    all {} certificates verify to {anchor_desc} ({})",
        bundle.verify.chained_ok,
        bundle.verify.anchored_roots.join(", ")
    );
}

fn status(
    group: fossroot_core::Group,
    offline: Option<std::path::PathBuf>,
    json: bool,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = load_bundle(group, offline)?;
    let user = diff_location(&bundle, Location::CurrentUser)?;
    let machine = diff_location(&bundle, Location::LocalMachine)?;

    if json {
        let out = serde_json::json!({
            "bundle": {
                "group": bundle.group,
                "version": bundle.version,
                "source": bundle.source,
                "zip_sha256": bundle.zip_sha256,
                "cert_count": bundle.certs.len(),
                "verify": bundle.verify,
            },
            "current_user": user,
            "local_machine": machine,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    print_verification(&bundle);
    println!();
    // Effective trust: a cert works if either the user or machine store has it.
    let effective = user
        .entries
        .iter()
        .zip(machine.entries.iter())
        .filter(|(u, m)| u.status == CertStatus::Installed || m.status == CertStatus::Installed)
        .count();
    let usable_total = user.installed + user.missing;
    println!("Effective trust: {effective}/{usable_total} DoD CAs usable on this machine");
    for (name, report) in [("Current User ", &user), ("Local Machine", &machine)] {
        let usable = report.installed + report.missing;
        println!(
            "{name}: {}/{} installed, {} missing{}{}",
            report.installed,
            usable,
            report.missing,
            if report.expired > 0 {
                format!(" ({} expired in bundle, ignored)", report.expired)
            } else {
                String::new()
            },
            if report.stale.is_empty() {
                String::new()
            } else {
                format!(", {} stale DoD certs", report.stale.len())
            }
        );
    }

    if verbose {
        println!();
        println!(
            "{:<44} {:<5} {:<10} {:<10}",
            "Certificate", "Store", "Expires", "User/Machine"
        );
        for (ue, me) in user.entries.iter().zip(machine.entries.iter()) {
            println!(
                "{:<44} {:<5} {:<10} {:?}/{:?}",
                ue.cert.display_name(),
                match ue.store {
                    StoreKind::Root => "ROOT",
                    StoreKind::Ca => "CA",
                },
                format_unix(ue.cert.not_after),
                ue.status,
                me.status
            );
        }
        for (loc, report) in [("CurrentUser", &user), ("LocalMachine", &machine)] {
            for stale in &report.stale {
                println!(
                    "STALE in {loc}: {} (expires {})",
                    stale.subject,
                    format_unix(stale.not_after)
                );
            }
        }
    } else {
        let missing_user: Vec<_> = user
            .entries
            .iter()
            .filter(|e| e.status == CertStatus::Missing)
            .collect();
        if !missing_user.is_empty() {
            println!("\nMissing from Current User:");
            for e in missing_user {
                println!(
                    "  {} [{}] expires {}",
                    e.cert.display_name(),
                    match e.store {
                        StoreKind::Root => "ROOT",
                        StoreKind::Ca => "CA",
                    },
                    format_unix(e.cert.not_after)
                );
            }
        }
        println!("\n(use --verbose for the full certificate list, --json for machine output)");
    }
    Ok(())
}

fn probe_write_or_explain(location: Location) -> Result<(), Box<dyn std::error::Error>> {
    let store = platform();
    for kind in [StoreKind::Root, StoreKind::Ca] {
        if let Err(e) = store.probe_write(SystemStore { location, kind }) {
            if location == Location::LocalMachine {
                return Err(format!(
                    "cannot write to the Local Machine store ({e}).\n\
                     Run this command from an elevated (Administrator) shell, or drop\n\
                     --machine to install for the current user only (no admin needed)."
                )
                .into());
            }
            return Err(e.into());
        }
    }
    Ok(())
}

fn confirm(prompt: &str, yes: bool) -> bool {
    if yes {
        return true;
    }
    eprint!("{prompt} [y/N] ");
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}

fn install(
    group: fossroot_core::Group,
    machine: bool,
    offline: Option<std::path::PathBuf>,
    prune: bool,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let location = if machine {
        Location::LocalMachine
    } else {
        Location::CurrentUser
    };
    probe_write_or_explain(location)?;
    let bundle = load_bundle(group, offline)?;
    print_verification(&bundle);
    let report = diff_location(&bundle, location)?;

    let to_install: Vec<_> = report
        .entries
        .iter()
        .filter(|e| e.status == CertStatus::Missing)
        .collect();
    let stale = if prune {
        report.stale.clone()
    } else {
        Vec::new()
    };

    if to_install.is_empty() && stale.is_empty() {
        println!(
            "\nNothing to do: store is already up to date with bundle v{}.",
            bundle.version
        );
        return Ok(());
    }

    println!("\nPlanned changes for {:?}:", location);
    for e in &to_install {
        println!(
            "  + {} → {} store (expires {})",
            e.cert.display_name(),
            match e.store {
                StoreKind::Root => "ROOT",
                StoreKind::Ca => "CA",
            },
            format_unix(e.cert.not_after)
        );
    }
    for s in &stale {
        println!("  - {} (stale, no longer in DISA bundle)", s.subject);
    }
    if !confirm("Apply these changes?", yes) {
        println!("Aborted; no changes made.");
        return Ok(());
    }

    let store = platform();
    let mut added = 0usize;
    for e in &to_install {
        store.add(
            SystemStore {
                location,
                kind: e.store,
            },
            &e.cert.der,
        )?;
        added += 1;
        println!("installed: {}", e.cert.display_name());
    }
    let mut pruned = 0usize;
    for s in &stale {
        for kind in [StoreKind::Root, StoreKind::Ca] {
            if store.remove_by_sha1(SystemStore { location, kind }, &s.sha1)? {
                pruned += 1;
                println!("removed stale: {}", s.subject);
            }
        }
    }
    println!("\nDone: {added} installed, {pruned} removed.");
    Ok(())
}

fn remove(
    group: fossroot_core::Group,
    machine: bool,
    offline: Option<std::path::PathBuf>,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let location = if machine {
        Location::LocalMachine
    } else {
        Location::CurrentUser
    };
    probe_write_or_explain(location)?;
    let bundle = load_bundle(group, offline)?;
    let report = diff_location(&bundle, location)?;
    let installed: Vec<_> = report
        .entries
        .iter()
        .filter(|e| e.status == CertStatus::Installed)
        .collect();
    if installed.is_empty() {
        println!(
            "No bundle certificates are present in {:?}; nothing to remove.",
            location
        );
        return Ok(());
    }
    println!(
        "This removes {} DoD certificates from {:?}:",
        installed.len(),
        location
    );
    for e in &installed {
        println!("  - {}", e.cert.display_name());
    }
    if !confirm("Remove them?", yes) {
        println!("Aborted; no changes made.");
        return Ok(());
    }
    let store = platform();
    let mut removed = 0usize;
    for e in &installed {
        if store.remove_by_sha1(
            SystemStore {
                location,
                kind: e.store,
            },
            &e.cert.sha1,
        )? {
            removed += 1;
        }
    }
    println!("Done: {removed} removed.");
    Ok(())
}

fn export(
    group: fossroot_core::Group,
    out: std::path::PathBuf,
    offline: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = load_bundle(group, offline)?;
    print_verification(&bundle);
    std::fs::create_dir_all(&out)?;
    let mut chain = String::new();
    for cert in &bundle.certs {
        let safe: String = cert
            .display_name()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        std::fs::write(out.join(format!("{safe}.cer")), &cert.der)?;
        chain.push_str(&pem_encode(&cert.der));
    }
    std::fs::write(out.join("dod_ca_chain.pem"), chain)?;
    println!(
        "\nExported {} certificates to {}",
        bundle.certs.len(),
        out.display()
    );
    Ok(())
}

fn pem_encode(der: &[u8]) -> String {
    // Minimal PEM writer (base64 with 64-char lines).
    const TBL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        b64.push(TBL[(n >> 18) as usize & 63] as char);
        b64.push(TBL[(n >> 12) as usize & 63] as char);
        b64.push(if chunk.len() > 1 {
            TBL[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        b64.push(if chunk.len() > 2 {
            TBL[n as usize & 63] as char
        } else {
            '='
        });
    }
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}
