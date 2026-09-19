# MailForensic AI - Forensic Demo Samples (.EML)

This directory contains standardized, RFC 5322-compliant `.eml` test vectors crafted for live demonstration and forensic evaluation at Smart India Hackathon (SIH) 2026.

---

## 📁 Sample Catalog & Pitch Matrix

| File | Scenario | Key Forensic Signals | Expected Outcome & System Response |
| :--- | :--- | :--- | :--- |
| **`01_legit_bank_statement.eml`** | Legitimate Bank of America Statement | • SPF: **PASS**<br>• DKIM: **PASS**<br>• DMARC: **PASS**<br>• RDAP Age: **10,000+ days**<br>• AbuseIPDB: **0% (Clean)** | **LOW RISK / SAFE**<br>🛡️ **Anti-False-Positive Shield (FPS) ENGAGED**<br>Suppresses false keyword alarms on terms like *"account balance"* and *"statement period"*. |
| **`02_stealth_bec_ceo_wire_fraud.eml`** | Executive BEC / CEO Wire Transfer | • **Zero URLs**, **Zero Attachments**<br>• SPF: **NEUTRAL** / DKIM: **NONE**<br>• Reply-To Divergence<br>• Cognitive Vector: `urgency=8`, `financial_coercion=true`, `authority_impersonation=true` | **CRITICAL RISK (88+)**<br>🚨 **Anti-False-Negative Hunter (FNE) ENGAGED**<br>Catches zero-day social engineering that traditional URL/signature filters completely miss. |
| **`03_credential_phish_microsoft365.eml`** | Microsoft 365 Credential Harvester | • Brand: **Microsoft**<br>• Typosquatting: `micros0ft-account-support.com`<br>• SPF: **FAIL** / DMARC: **FAIL**<br>• Raw IP Payload Link | **CRITICAL RISK (90+)**<br>⚠️ Brand Impersonation Alert + Multi-Vendor URL Blacklist match. |
| **`04_multihop_tor_exit_relay.eml`** | Advanced Multi-Hop Relay via Tor | • 3 `Received:` Transit Hops<br>• Origin IP: `185.220.101.5` (**Known Tor Exit Node**)<br>• Geo Divergence: Claims US Internal, hops via EU VPS | **CRITICAL RISK (94+)**<br>🌐 Anonymizer Node Flagged + Transit Hop Delay & Divergence Mapped on Leaflet Canvas. |
| **`05_urgent_payroll_direct_deposit.eml`** | HR Payroll Redirection on NRD | • Newly Registered Domain (< 30 days)<br>• Authority Impersonation: HR / ADP<br>• Threat Score escalation on unverified payroll update | **HIGH RISK (85+)**<br>📅 RDAP NRD Flagged + Cognitive Coercion Vector confirmed. |

---

## 🚀 How to Run in Demo

1. **Option A (Instant 1-Click in Browser)**:
   - Navigate to `/forensic/scan` on the dashboard.
   - Click any of the **Demo Presets** buttons at the top of the page.
   - The forensic engine will parse, deconstruct, and render the complete evidence report in ~1 second.

2. **Option B (Drag and Drop Actual Files)**:
   - Open your file manager to `demo_eml_samples/`.
   - Drag any `.eml` file into the upload zone on `/forensic/scan`.
   - Inspect the cryptographic signatures, hop transit map, and NS-BCT consensus arbitration.
