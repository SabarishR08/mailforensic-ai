// Popup logic: scan the current tab via the email-forensics backend
const scanBtn = document.getElementById("scan-button");
const statusEl = document.getElementById("status-text");
const resultEl = document.getElementById("result-text");

function setStatus(text, color = "#bfbfbf") {
  statusEl.textContent = text;
  statusEl.style.color = color;
}

function setResult(text, color = "#00cfff") {
  resultEl.textContent = text;
  resultEl.style.color = color;
}

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

async function scanCurrentTab() {
  try {
    setStatus("Grabbing current tab...");
    setResult("");
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    const url = await getActiveTabUrl();
    if (!url || !(url.startsWith("http://") || url.startsWith("https://"))) {
      setStatus("Only http/https URLs can be scanned", "#ff9f0a");
      scanBtn.disabled = false;
      scanBtn.textContent = "Scan URL";
      return;
    }

    setStatus("Contacting backend...");
    const base = await getApiBase();
    const resp = await fetch(base + "/check-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!resp.ok) {
      setStatus(`Backend error ${resp.status}`, "#ff453a");
      scanBtn.disabled = false;
      scanBtn.textContent = "Scan URL";
      return;
    }

    const data = await resp.json();
    const status = data.status || "Unknown";
    const severity = data.severity || "Unknown";
    const detectedBy = data.detected_by || "TI pipeline";

    const color = status === "Safe" ? "#34c759" : "#ff453a";
    setStatus("Scan complete", "#34c759");
    setResult(`${status} (severity: ${severity}) via ${detectedBy}`, color);
  } catch (err) {
    console.error("Popup scan error", err);
    setStatus("Backend unreachable — is the platform running?", "#ff453a");
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan URL";
  }
}

// Startup status: verify the backend is reachable
(async () => {
  try {
    const base = await getApiBase();
    const resp = await fetch(base + "/api/health", { cache: "no-store" });
    if (resp.ok) {
      setStatus("Connected to AI Email Forensics", "#34c759");
    } else {
      setStatus(`Backend responded ${resp.status}`, "#ff9f0a");
    }
  } catch {
    setStatus("Backend offline — pattern guard still active", "#ff9f0a");
  }
})();

scanBtn.addEventListener("click", scanCurrentTab);
