# Fossroot

**Open-source, single-binary manager for DoD PKI CA certificate trust stores.**
A modern, auditable replacement for DISA's InstallRoot utility.

![Fossroot GUI](docs/screenshot-main.png)

> ⚠️ **Unofficial community tool.** Fossroot is not affiliated with, endorsed by, or
> supported by the U.S. Department of War, DISA, or any government agency.
> "InstallRoot" is DISA's product; Fossroot is an independent open-source
> reimplementation of the same end-user need.

## What it does

Accessing DoW websites (OWA, myPay, MilConnect, …) from a personal computer
requires the DoD PKI root and intermediate CA certificates in your machine's
trust store. DISA's InstallRoot tool does this, but it is Windows-only, closed
source, and frozen at v5.6 (2024). Fossroot:

- **Fetches the latest official bundle** live from DISA's distribution point
  (`dl.dod.cyber.mil`) — Fossroot never ships certificates of its own.
- **Cryptographically verifies everything before touching your machine**:
  - the bundle's DISA-signed CMS checksum manifest is verified back to DoD
    root CAs whose SHA-256 fingerprints are **pinned in the source code**;
  - every certificate in the bundle must chain — with real signature
    verification (RSA & ECDSA) — to a pinned DoD root, or the bundle is
    rejected outright.
- **Shows you a full diff before any change**: what's installed, what's
  missing, what's expired, and which stale DoD CAs should be pruned.
- **Installs without admin** by default (per-user trust store; Windows shows
  its own confirmation for each root), or machine-wide from an elevated shell.
- **Uninstalls completely** — it removes exactly the certificates in the DISA
  bundle, nothing else, and leaves no other trace on your system.

## Why trust it?

You shouldn't trust *any* third-party root-CA installer blindly — including
this one. Fossroot's answer:

1. **100% open source** — every line that touches your trust store is in this
   repo, in memory-safe Rust.
2. **No bundled certificates** — trust flows from DISA's live distribution
   point plus root fingerprints pinned in [`verify.rs`](crates/fossroot-core/src/verify.rs),
   which you can check against DISA's published values yourself.
3. **Fail-closed verification** — if the manifest signature, a checksum, or a
   single chain fails to verify, nothing is installed.
4. **Single portable binary** — no installer, no services, no telemetry, no
   config files. Delete the exe and it's gone.

## Usage

```text
fossroot                 # GUI
fossroot status          # read-only: verification + coverage report
fossroot status --json   # machine-readable
fossroot install         # install missing certs (current user, no admin)
fossroot install --machine --prune   # machine-wide + remove stale DoD CAs (elevated)
fossroot remove          # uninstall everything the bundle manages
fossroot export --out d: # dump .cer files + PEM chain (for Firefox, WSL, etc.)
fossroot ... --offline bundle.zip    # air-gapped: use a hand-carried bundle
```

![Fossroot CLI status](docs/screenshot-cli.png)

The same verification runs whether you use the GUI or the CLI — the diff you see
is exactly what will change, and nothing is written until you confirm.

## Building

```bash
cargo build --release
```

Requires stable Rust. The result is a single self-contained executable.

## Roadmap

- Firefox/Thunderbird NSS profile support
- ECA / JITC / WCF bundle groups
- macOS and Linux trust-store backends (the core is already platform-agnostic)
- Java keystore support

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
