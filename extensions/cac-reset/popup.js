// CAC Reset popup. Talks to the local FossRoot Agent over native messaging.
// Read-only calls (ping, sc_status, trust_status) run on open; the two buttons
// invoke consent-gated agent actions (the agent shows a native OS dialog).

const HOST = "com.fossroot.agent";

// Brave masks its user-agent as Chrome, so sniffing the UA isn't enough — it
// exposes navigator.brave.isBrave(). Edge keeps the "Edg/" token. Resolved once
// at startup into `browser`, which the action buttons pass to the agent.
let browser = "chrome";
async function detectBrowser() {
  if (navigator.brave && (await navigator.brave.isBrave().catch(() => false))) {
    return "brave";
  }
  return /Edg\//.test(navigator.userAgent) ? "edge" : "chrome";
}

const $ = (id) => document.getElementById(id);
chrome.runtime.sendMessage("clear-badge");

// One request per connection; the agent answers and we disconnect.
function call(message) {
  return new Promise((resolve, reject) => {
    let port;
    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (e) {
      reject(e);
      return;
    }
    let settled = false;
    port.onMessage.addListener((resp) => {
      settled = true;
      resolve(resp);
      port.disconnect();
    });
    port.onDisconnect.addListener(() => {
      if (!settled) {
        const err = chrome.runtime.lastError;
        reject(new Error(err ? err.message : "agent disconnected"));
      }
    });
    port.postMessage(message);
  });
}

function agentMissing(err) {
  $("card-status").innerHTML =
    `<div class="err">Can't reach the FossRoot Agent.</div>` +
    `<div class="muted">Install FossRoot and run <code>fossroot-agent register</code>.</div>`;
  $("trust-status").style.display = "none";
  for (const b of ["btn-reset", "btn-autoselect"]) $(b).disabled = true;
  console.warn(err);
}

function renderCard(sc) {
  if (!sc.supported) {
    $("card-status").innerHTML = `<div class="muted">${sc.note || "Not supported on this OS."}</div>`;
    return;
  }
  const cac = sc.identities.find((i) => i.hardware_backed && i.dod) || sc.identities.find((i) => i.hardware_backed);
  if (sc.card_present) {
    $("card-status").innerHTML =
      `<div class="title ok">✓ CAC detected</div>` +
      `<div class="muted">${cac ? cac.common_name : "smart-card certificate present"}</div>` +
      `<div class="muted">If a site still rejects it, the browser session is stale — reset below.</div>`;
  } else {
    $("card-status").innerHTML =
      `<div class="title warn">No CAC detected</div>` +
      `<div class="muted">${sc.note || "Insert your CAC and reload."}</div>`;
  }
}

function renderTrust(st) {
  if (!st || !st.ok) {
    $("trust-status").style.display = "none";
    return;
  }
  const good = st.effective >= st.usable_total;
  $("trust-status").innerHTML =
    `<div class="title">DoD trust <span class="${good ? "ok" : "warn"}">${st.effective}/${st.usable_total}</span></div>` +
    `<div class="muted">${st.group_name} v${st.version} — ${good ? "up to date" : (st.usable_total - st.effective) + " missing (run FossRoot)"}</div>`;
}

function showResult(r) {
  const cls = r.ok ? "ok" : "warn";
  $("result").innerHTML = `<span class="${cls}">${r.detail || (r.ok ? "Done." : "No change.")}</span>`;
}

async function currentOrigin() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) return new URL(tab.url).origin + "/*";
  } catch (_) {}
  return null;
}

$("btn-reset").addEventListener("click", async () => {
  $("result").textContent = "Waiting for confirmation…";
  try {
    showResult(await call({ method: "relaunch_browser", browser: browser }));
  } catch (e) {
    showResult({ ok: false, detail: String(e.message || e) });
  }
});

$("btn-autoselect").addEventListener("click", async () => {
  const origin = await currentOrigin();
  if (!origin) {
    showResult({ ok: false, detail: "Open the DoD site in the active tab first." });
    return;
  }
  $("result").textContent = "Waiting for confirmation…";
  try {
    showResult(await call({ method: "apply_autoselect", browser: browser, origins: [origin] }));
  } catch (e) {
    showResult({ ok: false, detail: String(e.message || e) });
  }
});

(async () => {
  browser = await detectBrowser();
  try {
    await call({ method: "ping" });
    renderCard(await call({ method: "sc_status" }));
    renderTrust(await call({ method: "trust_status" }));
  } catch (e) {
    agentMissing(e);
  }
})();
