# FossRoot CAC Reset (Chrome / Edge)

Fixes the daily CAC annoyance: you open a `.mil` site, the browser cached a bad
or empty client-certificate choice for the session, and the only way to recover
is to **close the entire browser**. This extension detects that state and fixes
it in one click — via the local **FossRoot Agent** (browsers can't flush the TLS
client-cert cache themselves).

## What it does

- **Card status** — asks the agent whether a smart-card (CAC) certificate is
  actually readable, so you can tell "card not plugged in" from "card fine, the
  browser session is stale."
- **Reset browser for CAC** — the agent (after a native confirmation dialog)
  closes and reopens the browser with your tabs restored, starting a fresh
  session with an empty client-auth cache. **No admin needed.**
- **Stop asking on this site** — writes an `AutoSelectCertificateForUrls` policy
  so the site auto-picks your CAC. On hardened/managed machines the policy hive
  is admin-only; the agent detects that and tells you to use Reset instead.
- **Trust status** — also surfaces your FossRoot DoD trust coverage.

Detection is observational: the background worker watches for
`net::ERR_BAD_SSL_CLIENT_AUTH_CERT`-family errors on `*.mil` and badges the icon.

## Try it (dev)

```bash
cargo build -p fossroot-agent
./target/debug/fossroot-agent register     # allow-lists this extension's ID
```

Then load this folder at `chrome://extensions` → Developer mode → Load unpacked.
The committed `key` fixes the ID to `mfgimcojmphkmnmmpbiagoidoiccpegm`, which the
agent allow-lists by default.

## Honest limitations

No browser API can flush Chrome/Edge's in-memory client-cert selection without a
restart — so the "reset" really is a clean relaunch (tabs restored). The
prevention path (auto-select policy) needs admin on locked-down machines. Both
facts are surfaced in the UI rather than hidden.
