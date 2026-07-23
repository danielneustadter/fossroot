//! Native-messaging host registration for Chrome and Edge.
//!
//! Registration has two parts: a host **manifest** JSON file (naming the host,
//! the agent executable, and which extension IDs may connect), and a per-browser
//! **pointer** to that manifest. On Windows the pointer is a registry value; on
//! macOS/Linux the manifest simply lives in the browser's `NativeMessagingHosts`
//! directory. The spike targets Chrome + Edge, which share the protocol.

use std::io;
use std::path::PathBuf;

/// Native-messaging host name the extension connects to.
pub const HOST_NAME: &str = "com.fossroot.agent";

/// Default extension ID, derived from the committed extension public key in
/// `extension/manifest.json`. Overridable via `--extension-id` for dev loads
/// from a different key.
pub const DEFAULT_EXTENSION_ID: &str = "mfgimcojmphkmnmmpbiagoidoiccpegm";

#[derive(Clone, Copy)]
pub enum Browser {
    Chrome,
    Edge,
}

impl Browser {
    pub const ALL: [Browser; 2] = [Browser::Chrome, Browser::Edge];

    fn label(self) -> &'static str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Edge => "Edge",
        }
    }
}

fn manifest_json(exe: &str, extension_id: &str) -> String {
    // Hand-format to keep the (public, non-secret) manifest readable and
    // dependency-free.
    format!(
        "{{\n  \"name\": \"{HOST_NAME}\",\n  \"description\": \"Fossroot Agent\",\n  \
         \"path\": {exe},\n  \"type\": \"stdio\",\n  \
         \"allowed_origins\": [\"chrome-extension://{extension_id}/\"]\n}}\n",
        exe = serde_json::to_string(exe).unwrap(),
    )
}

/// Directory where we store the host manifest we generate.
fn manifest_dir() -> io::Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no config dir"))?;
    Ok(base.join("Fossroot"))
}

fn write_manifest(extension_id: &str) -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = manifest_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{HOST_NAME}.json"));
    std::fs::write(&path, manifest_json(&exe.to_string_lossy(), extension_id))?;
    Ok(path)
}

/// Register the host for Chrome and Edge. Returns a human-readable summary.
pub fn register(extension_id: &str) -> io::Result<String> {
    let manifest_path = write_manifest(extension_id)?;
    let mut lines = vec![format!("Wrote host manifest: {}", manifest_path.display())];
    for browser in Browser::ALL {
        register_browser(browser, &manifest_path)?;
        lines.push(format!("Registered for {}", browser.label()));
    }
    lines.push(format!("Allowed extension: {extension_id}"));
    Ok(lines.join("\n"))
}

pub fn unregister() -> io::Result<String> {
    let mut lines = Vec::new();
    for browser in Browser::ALL {
        unregister_browser(browser)?;
        lines.push(format!("Unregistered from {}", browser.label()));
    }
    if let Ok(dir) = manifest_dir() {
        let path = dir.join(format!("{HOST_NAME}.json"));
        if path.exists() {
            std::fs::remove_file(&path)?;
            lines.push(format!("Removed {}", path.display()));
        }
    }
    Ok(lines.join("\n"))
}

// --- Windows: registry pointer ---------------------------------------------

#[cfg(windows)]
fn registry_subkey(browser: Browser) -> &'static str {
    match browser {
        Browser::Chrome => r"Software\Google\Chrome\NativeMessagingHosts\com.fossroot.agent",
        Browser::Edge => r"Software\Microsoft\Edge\NativeMessagingHosts\com.fossroot.agent",
    }
}

#[cfg(windows)]
fn register_browser(browser: Browser, manifest_path: &std::path::Path) -> io::Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(registry_subkey(browser))?;
    key.set_value("", &manifest_path.to_string_lossy().to_string())
}

#[cfg(windows)]
fn unregister_browser(browser: Browser) -> io::Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.delete_subkey_all(registry_subkey(browser)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// --- macOS / Linux: manifest file in the browser's hosts directory ----------

#[cfg(not(windows))]
fn hosts_dirs(browser: Browser) -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    #[cfg(target_os = "macos")]
    let roots: &[&str] = match browser {
        Browser::Chrome => &["Library/Application Support/Google/Chrome/NativeMessagingHosts"],
        Browser::Edge => &["Library/Application Support/Microsoft Edge/NativeMessagingHosts"],
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let roots: &[&str] = match browser {
        Browser::Chrome => &[
            ".config/google-chrome/NativeMessagingHosts",
            ".config/chromium/NativeMessagingHosts",
        ],
        Browser::Edge => &[".config/microsoft-edge/NativeMessagingHosts"],
    };
    roots.iter().map(|r| home.join(r)).collect()
}

#[cfg(not(windows))]
fn register_browser(browser: Browser, manifest_path: &std::path::Path) -> io::Result<()> {
    let contents = std::fs::read(manifest_path)?;
    for dir in hosts_dirs(browser) {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{HOST_NAME}.json")), &contents)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn unregister_browser(browser: Browser) -> io::Result<()> {
    for dir in hosts_dirs(browser) {
        let path = dir.join(format!("{HOST_NAME}.json"));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_has_expected_shape() {
        let m = manifest_json(r"C:\x\fossroot-agent.exe", "abcdef");
        // Path must be JSON-escaped (backslashes doubled).
        assert!(m.contains(r#""path": "C:\\x\\fossroot-agent.exe""#));
        assert!(m.contains(r#""chrome-extension://abcdef/""#));
        assert!(m.contains(r#""type": "stdio""#));
        // And it must be valid JSON.
        let _: serde_json::Value = serde_json::from_str(&m).unwrap();
    }
}
