# Fossroot browser extension (spike)

A minimal Chrome/Edge (MV3) extension that shows your DoD PKI trust status in the
browser. It has no network access of its own — it talks only to the local
**Fossroot Agent** over [native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging),
and the agent does the (cryptographically verified) DISA fetch locally.

This is the **bridge spike**: it proves the browser ↔ native round-trip that the
planned browser-session helper and in-browser CAC signing will both build on.

## Try it (dev)

1. **Build and register the agent** (from the repo root):

   ```bash
   cargo build -p fossroot-agent
   ./target/debug/fossroot-agent register
   ```

   `register` writes the native-messaging host manifest and points Chrome and
   Edge at it (per-user, no admin). `./target/debug/fossroot-agent unregister`
   reverses it.

2. **Load the extension**: open `chrome://extensions` (or `edge://extensions`),
   enable **Developer mode**, click **Load unpacked**, and select this
   `extension/` folder. The committed `key` in `manifest.json` fixes the
   extension ID to `mfgimcojmphkmnmmpbiagoidoiccpegm`, which is the ID the agent
   allow-lists by default — so no ID juggling is needed.

3. Click the Fossroot toolbar icon. The popup asks the agent for `trust_status`
   and shows your coverage, e.g. **45/45 — DoD PKI v5.14, ✓ up to date**.

If you load the extension from a different key (no `key` field), pass your ID:
`fossroot-agent register --extension-id <your-id>`.

## What the agent exposes today

| Method | Purpose |
|---|---|
| `ping` | Liveness + agent version |
| `trust_status` | Read-only DoD/ECA/JITC/WCF coverage via `fossroot-core` |

Signing (#3) and browser-session remediation (#2) will add methods here, each
gated behind explicit per-action user consent.
