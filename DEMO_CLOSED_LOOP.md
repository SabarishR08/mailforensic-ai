# 🎯 SIH Demo — The Closed Loop: QR Phish → Flag → Click → Auto-Close

**One-line pitch:** *"We don't just detect the phish — we guard the employee after they click."*

**Total loop runtime:** ~90 seconds. Two presenters (A = platform, B = victim's laptop) make it snappier; one presenter works fine.

---

## 0. One-time setup (do BEFORE the jury walks in)

```bash
# 1) Platform — Flask backend on :5000 (serves dashboard + all APIs)
cd mailforensic-ai
python backend/app.py
#    → expect: "Running on http://127.0.0.1:5000"

# 2) Verify the platform is up (keep this tab open: the ThreatLog page)
curl -s http://localhost:5000/api/logs | head -c 200
#    → expect: JSON. If not, fix before the demo, not during.
```

**Load the extension (presenter B's laptop, once):**
1. `chrome://extensions` → enable **Developer mode** (top-right)
2. **Load unpacked** → select the `browser_extension/` folder
3. Pin **"AI Email Forensics — URL Guard"** to the toolbar
4. Confirm its config points at the platform: `browser_extension/config.js` → `API_BASE: "http://localhost:5000"` (default). Different machine? Click the extension icon → set the API base in the popup (it's runtime-configurable via `chrome.storage.local.apiBase`, no code edit needed).

**Pre-flight sanity (30 seconds, catches 90% of demo disasters):**

```bash
# Backend verdict path works and auto-enrolls monitoring:
curl -s -X POST http://localhost:5000/api/extension/check-url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://194.26.29.11/ms-login/auth"}' | python -m json.tool
#    → expect: status "Phishing"/"Malicious" (or threat verdict), severity not "safe"

# Monitoring queue accepted it:
curl -s http://localhost:5000/api/extension/api/monitoring/stats | python -m json.tool
#    → expect: "monitored_urls_count" >= 1
```

> ⚠️ **Live threat-intel dependency:** the verdict on first scan comes from URL threat intel (multi-vendor). On venue Wi-Fi this can be slow or blocked. **Run the pre-flight before the demo** — a once-scanned URL is cached in ThreatLog, and the extension also keeps a local sync of flagged URLs, so the loop works offline after one online scan. See **Fallback C** if the venue has no internet at all.

---

## 1. Scan the QR-phishing email (Presenter A — ~25s)

**Screen:** Email Scanner (`/email/scan`) or Forensic scan (`/forensic/scan`).

**File:** `demo_eml_samples/06_qr_phish_quishing.eml` — "Microsoft 365 Security" look-alike whose attachment is a **QR code that decodes to a raw-IP phishing URL** (`http://194.26.29.11/ms-login/auth`). This is the modern quishing pattern: nothing wrong in the text, weaponized payload hidden in the image.

**UI route:** drag `06_qr_phish_quishing.eml` into the forensic scan upload zone and run the scan.

**Or exact command (same pipeline the UI calls):**

```bash
curl -s -X POST http://localhost:5000/api/scan/text \
  -H "Content-Type: application/json" \
  -d "$(python - <<'PY'
import json
raw = open('demo_eml_samples/06_qr_phish_quishing.eml', encoding='utf-8').read()
print(json.dumps({'text': raw}))
PY
)" | python -m json.tool | grep -E '"prediction"|"confidence"|"risk_level"|"risk_score"|qr_analysis' -A2 | head -30
```

**Say while it runs:**
> *"Classic quishing. The text passes casual inspection — no obvious link. Our QR engine extracts the embedded code image from the attachment, decodes it with a three-tier fallback — OpenCV, Pyzbar, then a pure-PIL matrix decoder — and reveals the payload: a bare IP address, no domain, no TLS. Watch the platform flag it."*

**Point at:** the decoded QR URL in the results, the risk score, and the QR analysis section.

**What happens automatically:** flagged URLs from this scan are mirrored into the ThreatLog and enrolled into the URL monitoring queue (`threat_log_sync.sync_scan_result_to_threatlog`) — say this explicitly, it's the bridge to act 2.

**Fallback A (file drag breaks on stage Wi-Fi):** use the sample route instead — `POST /api/scan/sample` scans the built-in presets; sample `05`/`03` also flag URLs. Or scan via the text route above, which needs no file handling.

---

## 2. The click (Presenter B — ~15s)

**Screen:** any neutral page (e.g., open a new tab to a wiki page).

**Action:** type the flagged URL into a new tab and hit Enter:

```
http://194.26.29.11/ms-login/auth
```

(If offline/pre-flight mode: any URL you enrolled during pre-flight works identically.)

**Say while the page attempts to load:**
> *"Now the human moment. The mail was flagged, but a busy employee clicks anyway — QR codes are designed for exactly this. The URL Guard extension syncs the platform's flagged-URL list in the background, so the guard fires the instant navigation starts."*

---

## 3. The auto-close (the money shot — ~10s)

**What appears:** the tab **closes itself** before the phishing page renders. The extension's background service worker matched the URL against the platform verdict (`/check-url` + local flag list) and killed the tab (`chrome.tabs.remove`). The platform's monitoring stats tick up (auto-close/event counters).

**Show the receipt:**

```bash
curl -s http://localhost:5000/api/extension/api/monitoring/stats | python -m json.tool
```

Point at: `monitored_urls_count`, `status_breakdown`, `urls_with_status_changes` — plus the extension popup (click the guard icon), which shows the recent threat feed.

**Say:**
> *"Same platform, same intelligence — protecting the inbox and the browser. One scan now guards every employee on the network. That is the closed loop: detect, flag, guard, close."*

---

## 4. Jury-proof fallbacks (only if something misbehaves)

| Failure on stage | Fallback |
|---|---|
| **A. Venue Wi-Fi dead / threat-intel unreachable** | Run the pre-flight `check-url` once on hotspot before the demo → verdict cached in ThreatLog; the extension's local flag list still auto-closes offline. Zero-internet worst case: seed the flag list during setup (pre-flight), demo the loop fully offline. |
| **B. Drag-and-drop / UI upload glitches** | Use the `curl` text-scan route above (no file handling), or `POST /api/scan/sample` presets. |
| **C. Extension didn't auto-close** | Almost always the API base: click the guard icon → set API base to the platform's address, reload the extension. Second check: `chrome://extensions` → URL Guard → **service worker** console shows the `check-url` verdict. Re-click. |
| **D. Whole platform down on stage** | Screenshots/recording of the loop (make one the night before) + narrate the pre-flight curl outputs from this script — every step is reproducible from a terminal. |
| **E. Jury asks "does it false-positive?"** | Open `01_legit_bank_statement.eml` result (LOW RISK / FPS-Shield engaged) — one click on the saved ThreatLog entry. |
| **F. Jury asks "what if the URL goes bad later?"** | The monitoring queue re-scans enrolled URLs on a schedule (`scan_all_monitored`), tracks status changes, and auto-closes/ages-out — the stats endpoint shows `urls_with_status_changes` and `urls_near_auto_close` live. |

---

## 5. The 30-second version (if the jury cuts you off)

1. `POST /api/scan/text` with the QR `.eml` → CRITICAL, QR decodes to raw IP
2. Click `http://194.26.29.11/ms-login/auth` in a new tab
3. Tab closes itself. Show the guard popup. **"Detect, flag, guard, close."**

---

## Files & endpoints referenced

| Thing | Where |
|---|---|
| QR sample email | `demo_eml_samples/06_qr_phish_quishing.eml` (QR payload round-trip verified) |
| Email scan (text) | `POST /api/scan/text` (`backend/routes/email.py`) |
| Email scan (samples) | `POST /api/scan/sample` |
| Extension URL verdict | `POST /api/extension/check-url` (`backend/routes/extension.py`) |
| Monitoring stats | `GET /api/extension/api/monitoring/stats` |
| Auto-close logic | `browser_extension/background.js` (`chrome.tabs.remove` on threat verdicts) |
| ThreatLog mirror | `backend/services/threat_log_sync.py` |
| QR decode tiers | `backend/services/qr_service.py` (OpenCV → Pyzbar → PIL) |
