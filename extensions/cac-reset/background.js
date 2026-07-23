// Watches for TLS client-certificate handshake failures on DoD sites — the
// signature of "the browser cached a bad/empty CAC selection for this session."
// When one is seen, badge the toolbar icon so the user knows a reset will help.
// This is observational only (no request blocking).

const CLIENT_AUTH_ERRORS = new Set([
  "net::ERR_BAD_SSL_CLIENT_AUTH_CERT",
  "net::ERR_SSL_CLIENT_AUTH_CERT_NEEDED",
  "net::ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED",
  "net::ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS",
  "net::ERR_SSL_PROTOCOL_ERROR",
]);

function flag(origin) {
  chrome.action.setBadgeText({ text: "!" });
  chrome.action.setBadgeBackgroundColor({ color: "#d97706" });
  chrome.action.setTitle({
    title: "FossRoot: a CAC handshake just failed on " + origin + " — click to reset.",
  });
  chrome.storage.session.set({ lastFailure: { origin, at: Date.now() } });
}

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (CLIENT_AUTH_ERRORS.has(details.error)) {
      let origin = details.url;
      try {
        origin = new URL(details.url).origin;
      } catch (_) {}
      flag(origin);
    }
  },
  { urls: ["*://*.mil/*"] }
);

// Clear the flag once the user opens the popup (they're acting on it).
chrome.runtime.onMessage.addListener((msg) => {
  if (msg === "clear-badge") {
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setTitle({ title: "FossRoot CAC Reset" });
  }
});
