# AI Email Forensics — URL Guard (browser extension)

Browser companion for the AI Email Forensics platform. Ported from
`ai-threat-detection-security-ops` (Group B consolidation).

## What it does

1. **Blocks URLs flagged by email forensics** — every scanned email's flagged
   URLs are mirrored into the platform's ThreatLog; the extension syncs that
   list every 60s and instantly closes a tab if you click one of those URLs.
2. **Instant pattern blocking** — known phishing patterns (suspicious TLDs,
   IP hosts, excessive subdomains, deceptive keywords) close the tab in ~0.1ms.
3. **Background deep scan** — every visited URL is verified against
   VirusTotal, Google Safe Browsing and RDAP via the platform's
   `POST /check-url`; malicious verdicts close the tab and the URL is
   auto-enrolled in continuous monitoring.
4. **No sound alerts** — silent operation by design.

## Load it (Chrome / Edge / Brave)

1. Start the platform: `python backend/app.py` (default `http://localhost:5000`).
2. Open `chrome://extensions`, enable **Developer mode**.
3. Click **Load unpacked** → select this `browser_extension/` folder.
4. The popup shows "Connected to AI Email Forensics" when the backend is up.

## Pointing at a deployed backend

The API base defaults to `http://localhost:5000`. To target e.g. your Render
deployment, set `apiBase` in the extension's storage once (DevTools console on
the popup, or any extension page):

```js
chrome.storage.local.set({ apiBase: "https://<your-deploy>.onrender.com" });
```

Also update `host_permissions` in `manifest.json` to include that domain.

## Backend endpoints used

| Endpoint | Purpose |
|---|---|
| `POST /check-url` | Deep scan a URL (logs to ThreatLog, auto-enrolls monitoring) |
| `GET /api/recent_threats` | Cache-sync of email-flagged URLs (every 60s) |
| `POST /api/tab-activity` | Lightweight tab telemetry |
| `GET /api/monitoring/stats` | Monitoring queue stats (dashboard-ready) |
