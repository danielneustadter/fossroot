// Talks to the local Fossroot Agent over native messaging. One request per
// connection keeps the flow simple for the spike; the agent handles each and
// we disconnect. Nothing here reaches the network — the agent does the
// (verified) DISA fetch locally.

const HOST = "com.fossroot.agent";
const content = document.getElementById("content");
const foot = document.getElementById("foot");

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

function render(status) {
  const total = status.usable_total;
  const eff = status.effective;
  const allGood = eff >= total;
  const cls = allGood ? "ok" : "warn";
  const check = allGood ? "✓ up to date" : `${total - eff} missing`;

  content.innerHTML = `
    <div class="big ${cls}">${eff}/${total}</div>
    <div class="sub">${status.group_name} v${status.version} — ${check}</div>
    <div class="row"><span>Manifest signature</span><span class="ok">${
      status.manifest_signed ? "✓ verified" : "n/a"
    }</span></div>
    <div class="row"><span>Current user store</span><span>${
      status.user_missing === 0 ? "complete" : status.user_missing + " missing"
    }</span></div>
    <div class="row"><span>Local machine store</span><span>${
      status.machine_missing === 0 ? "complete" : status.machine_missing + " missing"
    }</span></div>
  `;
  foot.textContent = allGood
    ? "Your DoD certificates are current."
    : "Run Fossroot to install the missing certificates.";
}

function renderError(err) {
  content.innerHTML = `<div class="err">Couldn't reach the Fossroot Agent.</div>`;
  foot.innerHTML =
    `<span>${(err && err.message) || err}</span><br/>` +
    `Install Fossroot and run <code>fossroot-agent register</code>, then reopen this popup.`;
}

(async () => {
  try {
    await call({ method: "ping" });
    const status = await call({ method: "trust_status" });
    if (status && status.ok) {
      render(status);
    } else {
      renderError(new Error((status && status.error) || "agent returned an error"));
    }
  } catch (e) {
    renderError(e);
  }
})();
