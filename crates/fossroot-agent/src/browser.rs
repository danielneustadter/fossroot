//! Browser-session remediation for the CAC Reset extension.
//!
//! The honest limit (see the extension README): no API can flush Chrome/Edge's
//! in-memory TLS client-cert selection cache. So the two real fixes are
//! **prevention** — an `AutoSelectCertificateForUrls` policy so the browser
//! stops re-prompting — and **reset** — a clean relaunch that restores tabs,
//! which starts a fresh session with an empty client-auth cache.
//!
//! Every state-changing action here is gated behind an OS-native consent dialog
//! (`MessageBoxW`), never a browser-DOM prompt, so a hostile page cannot forge
//! consent.

use serde::Serialize;

#[derive(Clone, Copy, Debug)]
pub enum Browser {
    Chrome,
    Edge,
}

impl Browser {
    pub fn from_token(s: &str) -> Option<Browser> {
        match s.to_lowercase().as_str() {
            "chrome" => Some(Browser::Chrome),
            "edge" => Some(Browser::Edge),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Browser::Chrome => "Google Chrome",
            Browser::Edge => "Microsoft Edge",
        }
    }

    fn process(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome.exe",
            Browser::Edge => "msedge.exe",
        }
    }

    /// Registry subkey under HKCU for this browser's user policies.
    #[cfg(windows)]
    fn policy_subkey(self) -> &'static str {
        match self {
            Browser::Chrome => r"Software\Policies\Google\Chrome",
            Browser::Edge => r"Software\Policies\Microsoft\Edge",
        }
    }
}

#[derive(Serialize)]
pub struct ActionResult {
    pub ok: bool,
    pub method: &'static str,
    pub detail: String,
}

/// One `AutoSelectCertificateForUrls` entry: for `origin`, auto-pick a client
/// certificate whose issuer organization is the U.S. Government (i.e. the CAC).
fn autoselect_entry(origin: &str) -> String {
    // Chrome's policy value is a stringified JSON object.
    format!(
        r#"{{"pattern":"{origin}","filter":{{"ISSUER":{{"O":"U.S. Government"}}}}}}"#,
        origin = origin.replace('"', "")
    )
}

// --- Windows implementation -------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::*;
    use std::io;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    const AUTOSELECT_KEY: &str = "AutoSelectCertificateForUrls";

    /// Native yes/no consent. Returns true only on an explicit "Yes".
    pub fn consent(title: &str, body: &str) -> bool {
        use windows::core::HSTRING;
        use windows::Win32::UI::WindowsAndMessaging::{
            MessageBoxW, IDYES, MB_ICONWARNING, MB_YESNO,
        };
        let ret = unsafe {
            MessageBoxW(
                None,
                &HSTRING::from(body),
                &HSTRING::from(title),
                MB_YESNO | MB_ICONWARNING,
            )
        };
        ret == IDYES
    }

    pub fn apply_autoselect(browser: Browser, origins: &[String]) -> io::Result<ActionResult> {
        if origins.is_empty() {
            return Ok(ActionResult {
                ok: false,
                method: "apply_autoselect",
                detail: "no origins supplied".into(),
            });
        }
        if !consent(
            "FossRoot — stop CAC prompts",
            &format!(
                "Allow FossRoot to tell {} to auto-select your CAC certificate for:\n\n{}\n\n\
                 This writes a browser policy (you'll see \"Managed by your organization\"). \
                 You can undo it any time from the extension.",
                browser.label(),
                origins.join("\n")
            ),
        ) {
            return Ok(ActionResult {
                ok: false,
                method: "apply_autoselect",
                detail: "cancelled by user".into(),
            });
        }
        match write_autoselect_entries(browser, origins) {
            Ok(()) => Ok(ActionResult {
                ok: true,
                method: "apply_autoselect",
                detail: format!(
                    "wrote {} auto-select rule(s) for {}",
                    origins.len(),
                    browser.label()
                ),
            }),
            // On hardened machines HKCU\Software\Policies is writable only by
            // Administrators/SYSTEM. Report that plainly and steer the user to
            // the reset, which needs no policy write.
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(ActionResult {
                ok: false,
                method: "apply_autoselect",
                detail: "This machine's policy settings are locked to administrators, so the \
                         auto-select rule can't be written without admin rights. Use \"Reset \
                         browser for CAC\" instead — it needs no admin."
                    .into(),
            }),
            Err(e) => Err(e),
        }
    }

    /// The registry write, factored out from consent so it is integration-testable.
    pub(crate) fn write_autoselect_entries(browser: Browser, origins: &[String]) -> io::Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) =
            hkcu.create_subkey(format!("{}\\{}", browser.policy_subkey(), AUTOSELECT_KEY))?;
        for (i, origin) in origins.iter().enumerate() {
            key.set_value((i + 1).to_string(), &autoselect_entry(origin))?;
        }
        Ok(())
    }

    pub(crate) fn clear_autoselect_entries(browser: Browser) -> io::Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = format!("{}\\{}", browser.policy_subkey(), AUTOSELECT_KEY);
        match hkcu.delete_subkey_all(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn remove_autoselect(browser: Browser) -> io::Result<ActionResult> {
        clear_autoselect_entries(browser)?;
        Ok(ActionResult {
            ok: true,
            method: "remove_autoselect",
            detail: format!("cleared auto-select rules for {}", browser.label()),
        })
    }

    /// Locate the browser executable via the App Paths registry entry.
    fn exe_path(browser: Browser) -> io::Result<String> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let subkey = format!(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{}",
            browser.process()
        );
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = hklm.open_subkey(&subkey)?;
        let path: String = key.get_value("")?;
        Ok(path)
    }

    pub fn relaunch(browser: Browser) -> io::Result<ActionResult> {
        let exe = exe_path(browser).map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("could not locate {}", browser.label()),
            )
        })?;
        if !consent(
            "FossRoot — reset browser for CAC",
            &format!(
                "FossRoot will close and reopen {} to clear its stale CAC session.\n\n\
                 Your open tabs will be restored. Continue?",
                browser.label()
            ),
        ) {
            return Ok(ActionResult {
                ok: false,
                method: "relaunch_browser",
                detail: "cancelled by user".into(),
            });
        }
        // Graceful close (no /F): sends WM_CLOSE so the browser records its
        // session, then relaunch forcing session restore.
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", browser.process(), "/T"])
            .output();
        wait_for_exit(browser.process());
        std::process::Command::new(&exe)
            .arg("--restore-last-session")
            .spawn()
            .map_err(|e| io::Error::other(format!("relaunch failed: {e}")))?;
        Ok(ActionResult {
            ok: true,
            method: "relaunch_browser",
            detail: format!("relaunched {} with session restore", browser.label()),
        })
    }

    /// Poll until the process is gone (bounded), so relaunch doesn't collide
    /// with a profile still shutting down.
    fn wait_for_exit(process: &str) {
        for _ in 0..25 {
            let out = std::process::Command::new("tasklist")
                .args(["/FI", &format!("IMAGENAME eq {process}"), "/NH"])
                .output();
            let running = out
                .map(|o| String::from_utf8_lossy(&o.stdout).contains(process))
                .unwrap_or(false);
            if !running {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

// --- Non-Windows stubs (these are Chrome-on-Windows features for now) -------

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::io;

    fn unsupported(method: &'static str) -> io::Result<ActionResult> {
        Ok(ActionResult {
            ok: false,
            method,
            detail: "browser-session remediation is Windows-only in this build".into(),
        })
    }

    pub fn apply_autoselect(_b: Browser, _o: &[String]) -> io::Result<ActionResult> {
        unsupported("apply_autoselect")
    }
    pub fn remove_autoselect(_b: Browser) -> io::Result<ActionResult> {
        unsupported("remove_autoselect")
    }
    pub fn relaunch(_b: Browser) -> io::Result<ActionResult> {
        unsupported("relaunch_browser")
    }
}

pub use imp::{apply_autoselect, relaunch, remove_autoselect};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autoselect_entry_is_valid_json_with_gov_filter() {
        let e = autoselect_entry("https://*.mil");
        let v: serde_json::Value = serde_json::from_str(&e).unwrap();
        assert_eq!(v["pattern"], "https://*.mil");
        assert_eq!(v["filter"]["ISSUER"]["O"], "U.S. Government");
    }

    #[test]
    fn browser_token_parsing() {
        assert!(matches!(
            Browser::from_token("Chrome"),
            Some(Browser::Chrome)
        ));
        assert!(matches!(Browser::from_token("edge"), Some(Browser::Edge)));
        assert!(Browser::from_token("firefox").is_none());
    }

    /// Verifies the winreg create → set → read → delete mechanics against a
    /// scratch HKCU key we can always write (reversible, no admin), and reports
    /// whether the real Chrome policy path is writable on this machine (it is
    /// admin-only on hardened boxes). Gated so normal `cargo test`/CI never
    /// touch the registry.
    #[cfg(windows)]
    #[test]
    fn autoselect_registry_roundtrip() {
        if std::env::var_os("FOSSROOT_REG_TEST").is_none() {
            eprintln!("skipped: set FOSSROOT_REG_TEST=1 to run");
            return;
        }
        use std::process::Command;
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        // 1. Mechanics against a writable scratch key (mirrors write_autoselect_entries).
        const SCRATCH: &str = r"Software\FossRootTest\AutoSelect";
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu.create_subkey(SCRATCH).unwrap();
        key.set_value("1", &super::autoselect_entry("https://*.mil"))
            .unwrap();
        let got: String = key.get_value("1").unwrap();
        let v: serde_json::Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["filter"]["ISSUER"]["O"], "U.S. Government");
        hkcu.delete_subkey_all(r"Software\FossRootTest").unwrap();

        // 2. Report (do not assert) whether the real policy path is writable.
        match super::imp::write_autoselect_entries(Browser::Chrome, &["https://*.mil".into()]) {
            Ok(()) => {
                let out = Command::new("reg")
                    .args([
                        "query",
                        r"HKCU\Software\Policies\Google\Chrome\AutoSelectCertificateForUrls",
                        "/s",
                    ])
                    .output()
                    .unwrap();
                assert!(String::from_utf8_lossy(&out.stdout).contains("U.S. Government"));
                super::imp::clear_autoselect_entries(Browser::Chrome).unwrap();
                eprintln!("policy path IS writable on this machine");
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "policy path is admin-only here (expected on hardened machines) — \
                           the apply_autoselect RPC returns a friendly message for this case"
                );
            }
            Err(e) => panic!("unexpected error writing policy path: {e}"),
        }
    }
}
