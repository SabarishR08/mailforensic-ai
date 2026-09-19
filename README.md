# Mailforensic AI

![License](https://img.shields.io/badge/license-MIT-green) ![Language](https://img.shields.io/badge/language-Python-informational) ![Docker](https://img.shields.io/badge/docker-ready-2496ed) ![Deploy](https://img.shields.io/badge/deploy-Render-46e3b7)


## Overview

AI-powered email threat detection, geolocation and forensic intelligence platform — SIH 2026, AICTE problem statement

## Architecture

```text
Browser / UI
     │   HTTP
     ▼
Flask, WebSockets (Flask-SocketIO) app (handlers: api, dashboard, email, forensic)
     │
     ├──▶ Services — email_scanner, forensic_analyzer, forensic_report, gemini_service, geo_service, gmail_service, …
     ├──▶ Database — SQLite
     └──▶ External services — Google Gemini, VirusTotal, Google Safe Browsing, AbuseIPDB, Gmail API, Google APIs, GeoIP · ML models — scikit-learn, XGBoost, LightGBM, PyTorch, Transformers
```

## Tech Stack

- **Language:** Python
- **Backend:** Flask, WebSockets (Flask-SocketIO)
- **Database:** SQLite
- **ML:** scikit-learn, XGBoost, LightGBM, PyTorch, Transformers
- **Integrations:** Google Gemini, VirusTotal, Google Safe Browsing, AbuseIPDB, Gmail API, Google APIs, GeoIP
- **Deployment:** Docker container / Render (render.yaml)

## Getting Started

### Prerequisites

- Python 3.10+
- Docker (optional, for container runs)

### 1. Clone

```bash
git clone https://github.com/SabarishR08/mailforensic-ai.git
cd mailforensic-ai
```

### 2. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env   # then fill in values
```

Environment variables used: `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `SAFE_BROWSING_API_KEY`, `ABUSEIPDB_API_KEY`, `GMAIL_CREDENTIALS_JSON`, `GMAIL_REFRESH_TOKEN`, `FLASK_SECRET_KEY`, `DEBUG_MODE`, `PORT`.

External services involved: Google Gemini, VirusTotal, Google Safe Browsing, AbuseIPDB, Gmail API, Google APIs, GeoIP.

### 4. Run

```bash
python backend/app.py
```

```bash
python backend/routes/dashboard.py
```

### (Alternative) Run with Docker

```bash
docker compose up --build
```

### React Frontend (optional SPA)

The dashboard UI also ships as a **React + Vite + TypeScript** SPA in [`frontend/`](frontend/). It talks to the exact same Flask APIs and Socket.IO events, so the backend is unchanged.

```bash
cd frontend
npm install
npm run dev        # dev server on :5173, proxies /api + Socket.IO to Flask on :5000
npm run build      # production build → frontend/dist
```

Flask automatically serves the built SPA (instead of the Jinja templates) whenever `frontend/dist/index.html` exists. Control it explicitly with the `FRONTEND_SPA` env var (`1` = SPA, `0` = legacy Jinja). API/PDF/Socket.IO routes behave identically in both modes. On Render, add a build step (`npm ci && npm run build` in `frontend/`) before starting the web service.

> The old Jinja2 templates in `dashboard/templates/` remain in the repo and stay fully functional (set `FRONTEND_SPA=0`) — safe to remove once the SPA is battle-tested.

## Deployment

Defined in `render.yaml` (web service `ai-email-forensics`) with `autoDeploy` enabled — pushes to the default branch trigger a Render deploy.


---

> **SIH26106** — Smart India Hackathon 2026 | AICTE Problem Statement
> [Live Demo](https://sih26106-email-forensics.onrender.com/dashboard)

---

## Quick Links

| Resource | Link |
|----------|------|
| **Live Platform** | [sih26106-email-forensics.onrender.com](https://sih26106-email-forensics.onrender.com/dashboard) |
| **Training Datasets** | [Google Drive Folder](https://drive.google.com/drive/folders/1MqyAdNHZFGVQzfDx5VwszbqbiEgm-Wg0?usp=drive_link) |
| **Colab Training Notebook** | [Open in Colab](https://colab.research.google.com/drive/1Rqz3TkPnmXebt8jz39oWvjM6Q-P4J-T1?usp=sharing) |
| **GitHub Repository** | [github.com/SabarishR08/mailforensic-ai](https://github.com/SabarishR08/mailforensic-ai) |

---

## Problem Statement

Build an AI-powered platform that detects email-based threats (phishing, BEC, malware), traces sender geolocation, and generates forensic intelligence reports — combining ML classification, threat intelligence fusion, email header forensics, and geolocation risk scoring into a single dashboard.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │Dashboard │ │ Scanner  │ │Forensic  │ │Threat    │ │ Live     │ │
│  │          │ │          │ │.eml      │ │Intel     │ │Demo      │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │
├───────┼────────────┼────────────┼────────────┼────────────┼─────────┤
│       │         FLASK + SOCKETIO + JINJA2 TEMPLATES         │       │
├───────┼────────────┼────────────┼────────────┼────────────┼─────────┤
│                        ORCHESTRATION LAYER                         │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                   email_scanner.py                          │    │
│  │  ML → Threat Intel → Geo → Forensics → Risk Score          │    │
│  └─────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────┤
│                         SERVICE LAYER                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │ml_       │ │threat_   │ │geo_      │ │forensic_ │ │risk_     │ │
│  │predictor │ │intel     │ │service   │ │analyzer  │ │scoring   │ │
│  │(XGB+LGB  │ │(VT+SB+   │ │(MaxMind+ │ │(SPF/     │ │(weighted │ │
│  │+BERT opt)│ │ RDAP+    │ │ ipapi)   │ │ DKIM/    │ │ composite│ │
│  │          │ │ AbuseIP) │ │          │ │ DMARC)   │ │ 0-100)   │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                           │
│  │gemini_   │ │gmail_    │ │forensic_ │                           │
│  │service   │ │service   │ │report    │                           │
│  │(NLP+AI)  │ │(OAuth)   │ │(PDF)     │                           │
│  └──────────┘ └──────────┘ └──────────┘                           │
├─────────────────────────────────────────────────────────────────────┤
│                          DATA LAYER                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                           │
│  │SQLAlchemy│ │ML Models │ │GeoLite2  │                           │
│  │(SQLite)  │ │(.pkl +   │ │(.mmdb)   │                           │
│  │          │ │BERTopt.) │ │          │                           │
│  └──────────┘ └──────────┘ └──────────┘                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| **ML Email Detection** | Yes | Adaptive ensemble: XGBoost (97.39%) + LightGBM (97.56%) by default; auto-upgrades to full 3-model ensemble with DistilBERT (98.92%) when `requirements-torch.txt` is installed. Live Render deployment runs XGB+LGB only. All figures from evaluated test-set results in `model_comparison.json`. |
| **Geolocation** | Yes | IP → City/Country/ASN via MaxMind GeoLite2 + ipapi.co fallback |
| **Email Forensics** | Yes | SPF/DKIM/DMARC analysis, Received chain tracing, per-hop geo |
| **Unified Risk Scoring** | Yes | Weighted 6-signal composite (ML + intel + auth + geo + forensic + content) |
| **Threat Intelligence** | Yes | VirusTotal + Google SafeBrowsing + PhishTank + RDAP + AbuseIPDB |
| **PDF Forensic Reports** | Yes | Downloadable per-email forensic breakdown (ReportLab) |
| **Threat Map** | Yes | Leaflet.js geospatial visualization of threat origins |
| **Live Demo Mode** | Yes | Real-time SocketIO email analysis with streaming results |
| **Forensic .eml Upload** | Yes | Drag-and-drop .eml file analysis without Gmail credentials |
| **Threat Intel Dashboard** | Yes | Phishing trends, auth failure rates, country heatmap (Chart.js) |
| **Gmail Integration** | Yes | Live inbox scan with full pipeline analysis (OAuth 2.0) |
| **AI Enrichment** | Yes | Gemini NLP for explainable phishing classification |
| **Unit Tests** | Yes | 95 passing tests (ML pipeline + forensics + services) |
| **Docker Support** | Yes | One-command deployment via Docker Compose |
| **Render Deployment** | Yes | Free-tier live deployment with auto-deploy from GitHub |

---

## Machine Learning Models

### Training Overview

Models are trained on **Google Colab** with T4 GPU using 7 curated email datasets totaling **~30,000+ emails**. The training pipeline:

1. **Load & Merge** — 7 datasets with explicit column mapping (no fuzzy guessing)
2. **Text Cleaning** — URL/Email/IP tokenization, lemmatization, stop-word removal (keeping phishing-relevant words)
3. **Feature Engineering** — 30,000 TF-IDF features + 19 handcrafted features
4. **Train 3 Models** — XGBoost → LightGBM → DistilBERT (sequential)
5. **Evaluate** — Accuracy, Precision, Recall, F1, AUC-ROC, confusion matrices
6. **Save** — Models + vectorizer + feature list to Google Drive

### Model Architecture

```
Input Email Text
    │
    ├──→ TF-IDF Vectorizer (30,000 features, n-grams 1-3)
    │         │
    │         ├──→ XGBoost (400 trees, depth=7, lr=0.08)
    │         │         → phishing probability: xgb_prob
    │         │
    │         ├──→ LightGBM (500 trees, leaves=63, lr=0.05)
    │         │         → phishing probability: lgb_prob
    │         │
    │         └──→ Manual Features (19 handcrafted)
    │                   → appended to TF-IDF sparse matrix
    │
    ├──→ DistilBERT Tokenizer (max_length=256)
    │         │
    │         └──→ DistilBERT (fine-tuned, 3 epochs, lr=2e-5)
    │                   → phishing probability: bert_prob
    │
    └──→ Weighted Ensemble
              │
              ├── BERT available:  0.6 × bert + 0.2 × xgb + 0.2 × lgb
              ├── BERT unavailable: 0.5 × xgb + 0.5 × lgb
              │
              └──→ prediction: phishing (≥0.5) | legitimate (<0.5)
                   confidence: ensemble probability
                   risk_level: HIGH (>0.8) | MEDIUM (>0.5) | LOW (≤0.5)
```

### 19 Handcrafted Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | `char_count` | Total character count |
| 2 | `word_count` | Total word count |
| 3 | `url_count` | Number of URLs in text |
| 4 | `email_count` | Number of email addresses |
| 5 | `exclaim_count` | Exclamation mark count |
| 6 | `question_count` | Question mark count |
| 7 | `caps_ratio` | Ratio of uppercase characters |
| 8 | `digit_ratio` | Ratio of numeric characters |
| 9 | `html_tag_count` | Number of HTML tags |
| 10 | `phishing_kw_count` | Phishing keyword matches |
| 11 | `credential_threat_count` | Credential-harvesting phrases |
| 12 | `account_word_count` | Neutral account vocabulary |
| 13 | `has_ip_addr` | Contains raw IP address |
| 14 | `has_urgency` | Contains urgency language |
| 15 | `has_money_words` | Contains financial terms |
| 16 | `has_credential_threat` | Contains credential threats |
| 17 | `unique_word_ratio` | Vocabulary diversity |
| 18 | `avg_word_len` | Average word length |
| 19 | `suspicious_tld` | Uses suspicious TLD (.xyz, .tk, .ml, etc.) |

### Training Results

| Model | Accuracy | Precision | Recall | F1 Score | AUC-ROC | Size |
|-------|----------|-----------|--------|----------|---------|------|
| **XGBoost** | 97.39% | 94.82% | 97.54% | 96.16% | 0.9957 | 944 KB |
| **LightGBM** | 97.56% | 95.40% | 97.42% | 96.40% | 0.9959 | 3.1 MB |
| **DistilBERT** | 98.92% | 98.44% | 98.32% | 98.38% | 0.9991 | 268 MB |
| **XGB+LGB Ensemble** | ~97.5% | ~95.1% | ~97.5% | ~96.4% | ~0.996 | 4.0 MB |
| **Full 3-Model Ensemble** | **98.9%** | **98.4%** | **98.3%** | **98.4%** | **0.999** | 272 MB |

> **Note:** Individual model figures (XGBoost, LightGBM, DistilBERT) are measured test-set results from `model_comparison.json`. XGB+LGB Ensemble figures are estimated from the individual scores; the Full 3-Model Ensemble figures are DistilBERT-weighted and match the DistilBERT test-set result.

### Deployment Configurations

| Config | Models Used | RAM | Accuracy | Cost |
|--------|-------------|-----|----------|------|
| **Free Tier** (Render) | XGBoost + LightGBM | ~200 MB | 97.5% | Free |
| **Full Ensemble** | XGB + LGB + DistilBERT | ~600 MB | 98.9% | $7/mo |

> The platform auto-detects whether DistilBERT is available and gracefully falls back to XGB+LGB.

---

## Training Datasets

All datasets are hosted on [Google Drive](https://drive.google.com/drive/folders/1MqyAdNHZFGVQzfDx5VwszbqbiEgm-Wg0?usp=drive_link) and also included locally in `training/datasets/`.

| # | Dataset | Rows | Size | Source | Description |
|---|---------|------|------|--------|-------------|
| 1 | `Phishing_Email.csv` | ~18,000 | 52 MB | Kaggle | Main phishing vs legitimate email corpus |
| 2 | `phishing_legitimate_emails.csv` | ~7,000 | 0.8 MB | Kaggle | Spam/ham classifier dataset |
| 3 | `human_legit.csv` | 1,000 | 4.4 MB | Human-written | Legitimate emails written by humans |
| 4 | `human_phishing.csv` | 1,000 | 1.3 MB | Human-written | Phishing emails crafted by humans |
| 5 | `llm_legit.csv` | 1,000 | 0.6 MB | LLM-generated | Legitimate emails generated by LLMs |
| 6 | `llm_phishing.csv` | 1,000 | 0.7 MB | LLM-generated | Sophisticated phishing emails generated by LLMs |
| 7 | `mail_data.csv` | ~5,000 | 0.5 MB | Kaggle | Spam classification dataset |

**Total**: ~34,000+ emails across 7 sources

### Dataset Composition

```
Training Data Mix
├── Phishing Emails (label=1)
│   ├── Real-world phishing from Kaggle datasets
│   ├── Human-crafted phishing (adversarial)
│   └── LLM-generated phishing (sophisticated, evasive)
├── Legitimate Emails (label=0)
│   ├── Real-world legitimate from Kaggle datasets
│   ├── Human-written legitimate
│   └── LLM-generated legitimate
└── Spam (mapped to label=1)
    └── Traditional spam corpus
```

> **Why this mix matters**: Including human-written AND LLM-generated phishing ensures the model handles both classic模板-based phishing and modern AI-crafted spear-phishing that evades traditional keyword filters.

### Dataset Bug Fixes Applied

The Colab notebook includes fixes for issues found in earlier notebook versions:

| Bug | Root Cause | Fix |
|-----|-----------|-----|
| `ParserError: Expected 7 fields, saw 13` | `llm_phishing.csv` has unquoted commas in email text | Custom CSV parser splits on last comma only |
| `torch.cuda.amp.GradScaler()` deprecated | PyTorch 2.4+ moved to `torch.amp` | Changed to `torch.amp.GradScaler("cuda")` |
| `torch.cuda.amp.autocast()` deprecated | Same PyTorch change | Changed to `torch.amp.autocast("cuda")` |
| `nltk.download('punkt')` deprecated | NLTK 3.9+ renamed tokenizers | Changed to `punkt_tab` |
| `use_label_encoder=False` removed | XGBoost 2.0+ removed parameter | Removed from XGBClassifier |

---

## Quick Start

### Option 1: Live Demo (Already Deployed)

Visit **[sih26106-email-forensics.onrender.com](https://sih26106-email-forensics.onrender.com/dashboard)** — no setup needed.

### Option 2: Train Models (Google Colab)

1. **Upload datasets** to Google Drive → `MyDrive/datasets/` ([Drive Link](https://drive.google.com/drive/folders/1MqyAdNHZFGVQzfDx5VwszbqbiEgm-Wg0?usp=drive_link))
2. **Open notebook** → [Colab Link](https://colab.research.google.com/drive/1Rqz3TkPnmXebt8jz39oWvjM6Q-P4J-T1?usp=sharing)
3. **Enable GPU**: Runtime → Change runtime type → **T4 GPU**
4. **Run all**: Runtime → Run all (Ctrl+F9)
5. **Wait** ~45-90 min → models save to `MyDrive/trained_models/`
6. **Download** `.pkl` files → place in `backend/ml/models/`

### Option 3: Run Locally

```bash
# Clone the repo
git clone https://github.com/SabarishR08/mailforensic-ai.git
cd mailforensic-ai

# Install dependencies
pip install -r requirements.txt

# Copy trained models (from Colab or Google Drive)
# Place .pkl files in backend/ml/models/

# Run
python -m backend.app
# → http://localhost:5000/dashboard
```

### Option 4: Docker

```bash
docker compose up --build
# → http://localhost:5000/dashboard
```

---

## API Endpoints

### Email Classification

```bash
# Classify email text
curl -X POST https://sih26106-email-forensics.onrender.com/email/api/scan/text \
  -H "Content-Type: application/json" \
  -d '{"text": "Dear user, your account has been suspended. Click here to verify."}'

# Response:
# {"prediction":"phishing","confidence":0.9895,"model_loaded":true}
```

### All Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/stats` | Scan statistics |
| POST | `/email/api/scan/text` | Classify email text (ML only) |
| POST | `/email/api/scan/gmail` | Scan Gmail inbox |
| POST | `/forensic/api/analyze` | Full forensic analysis (headers + ML + geo) |
| POST | `/forensic/api/analyze-eml` | Analyze uploaded .eml file |
| GET | `/forensic/api/report/pdf/<id>` | Download forensic PDF report |
| GET | `/api/threat-intel/summary` | Threat intelligence summary |
| GET | `/api/threat-intel/trends` | Phishing trends over time |
| GET | `/api/threat-intel/distribution` | Risk distribution charts |
| GET | `/api/threat-intel/top-sources` | Top threat source countries |
| GET | `/api/threat-intel/auth-trends` | SPF/DKIM/DMARC failure rates |
| GET | `/api/geo/threats` | Geo-tagged threat data |
| WS | `start_demo_scan` | SocketIO real-time scan |

### Dashboard Pages

| URL | Page |
|-----|------|
| `/dashboard` | Main dashboard — stats, recent scans, geo map |
| `/email/scan` | Email scanner — Gmail + manual text input |
| `/email/demo` | Live demo — real-time SocketIO analysis |
| `/forensic/scan` | .eml file upload — drag & drop forensics |
| `/forensic/report/<id>` | Forensic drill-down — auth chain, routing hops, risk |
| `/dashboard/threat-intel` | Threat intel — phishing trends, charts |

---

## Project Structure

```
mailforensic-ai/
├── backend/
│   ├── ml/                          # Trained models + inference
│   │   ├── models/
│   │   │   ├── xgb_email_threat_model.pkl    (944 KB) — XGBoost
│   │   │   ├── lgb_email_threat_model.pkl    (3.1 MB) — LightGBM
│   │   │   ├── tfidf_vectorizer.pkl          (1.2 MB) — TF-IDF
│   │   │   ├── feature_cols.json             (1 KB)   — Feature names
│   │   │   ├── model_comparison.json         (1 KB)   — Accuracy metrics
│   │   │   └── distilbert_email_threat/      (268 MB) — DistilBERT (optional)
│   │   └── email_classifier.py       # Standalone inference module
│   ├── ml_pipeline/                  # Training pipeline (reference code)
│   │   ├── data_loader.py            # Dataset loading + merging
│   │   ├── feature_engineering.py    # TF-IDF + manual features
│   │   ├── model_builder.py          # Ensemble model builder
│   │   ├── evaluator.py              # Metrics + confusion matrix
│   │   └── pipeline.py               # End-to-end orchestrator
│   ├── services/                     # Core services
│   │   ├── ml_predictor.py           # ML prediction (XGB+LGB, auto-detects BERT)
│   │   ├── geo_service.py            # MaxMind GeoLite2 + ipapi fallback
│   │   ├── forensic_analyzer.py      # SPF/DKIM/DMARC + routing chain + per-hop geo
│   │   ├── forensic_report.py        # PDF generation (ReportLab)
│   │   ├── threat_intelligence.py    # VT + SafeBrowsing + RDAP + AbuseIPDB
│   │   ├── risk_scoring.py           # Weighted 6-signal composite (0-100)
│   │   ├── gemini_service.py         # Google Gemini NLP classification
│   │   ├── gmail_service.py          # Gmail API (OAuth 2.0)
│   │   └── email_scanner.py          # Orchestrates full pipeline per email
│   ├── routes/                       # Flask blueprints
│   │   ├── dashboard.py              # Dashboard + threat intel pages
│   │   ├── email.py                  # Email scan + SocketIO demo
│   │   ├── forensic.py               # .eml upload + forensic reports
│   │   └── api.py                    # REST API endpoints
│   ├── models.py                     # SQLAlchemy models (ThreatLog, EmailScanResult)
│   ├── extensions.py                 # SocketIO extension
│   └── app.py                        # Flask entry point
├── dashboard/templates/              # Jinja2 templates (7 pages)
│   ├── base.html                     # Sidebar nav + Leaflet.js + Bootstrap
│   ├── dashboard.html                # Stats cards + recent scans + geo map
│   ├── email_scanner.html            # Gmail scan + manual text scan
│   ├── demo.html                     # Full-screen live demo mode
│   ├── forensic_eml.html             # .eml upload + drag-and-drop
│   ├── forensic_report.html          # Forensic drill-down view
│   └── threat_intel.html             # Chart.js trend analytics
├── training/
│   ├── SIH26106_Email_Threat_Detection_Training.ipynb  # THE notebook
│   └── datasets/                     # Local copy of 7 training datasets
├── tests/                            # 95 unit tests
│   ├── test_ml_pipeline.py           # ML pipeline tests (32)
│   ├── test_forensic_analyzer.py     # Forensic analyzer tests (38)
│   └── test_services.py              # Risk scoring + URL utils tests (25)
├── Dockerfile                        # Container deployment
├── docker-compose.yml                # One-command launch
├── docker-entrypoint.sh              # Model check + DB init
├── render.yaml                       # Render free-tier config
├── requirements.txt                  # Python dependencies (lightweight)
├── requirements-torch.txt            # Optional: DistilBERT support
├── .env.example                      # API key template
└── README.md                         # This file
```

**Stats**: 75 files | 32 Python | 7 HTML templates | 95 unit tests

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11, Flask, Flask-SocketIO, SQLAlchemy |
| **ML Models** | XGBoost, LightGBM, DistilBERT (Transformers) |
| **ML Pipeline** | scikit-learn, TF-IDF, scipy (sparse matrices) |
| **Frontend** | Bootstrap 5, Chart.js, Leaflet.js, SocketIO client |
| **GeoLocation** | MaxMind GeoLite2, ipapi.co fallback |
| **Threat Intel** | VirusTotal, Google SafeBrowsing, PhishTank, RDAP, AbuseIPDB |
| **AI Enrichment** | Google Gemini (NLP classification) |
| **Forensics** | Custom SPF/DKIM/DMARC parser, ReportLab (PDF) |
| **Database** | SQLite (SQLAlchemy ORM) |
| **Deployment** | Render (free tier), Docker, GitHub Actions |

---

## Testing

```bash
# Run all 95 tests
python -m pytest tests/ -v

# Run specific test suite
python -m pytest tests/test_ml_pipeline.py -v      # 32 tests
python -m pytest tests/test_forensic_analyzer.py -v # 38 tests
python -m pytest tests/test_services.py -v          # 25 tests
```

All tests use synthetic data and mocks — no network, no trained models, no databases required.

---

## Contributors

| Member | Role | Track |
|--------|------|-------|
| **Sabarish R** | ML Integration + Architecture | Model training, pipeline, deployment |
| **Vignesh** | Geolocation | IP lookup, country risk scoring, map visualization |
| **Shafeeq** | Forensic Intelligence | Header forensics, routing chain, PDF reports |
| **Rohith** | Dashboard + Demo | UI templates, live demo, browser extension |

---

## License

This project was developed for **Smart India Hackathon 2026** (SIH26106). For academic and demonstration purposes.

---

<p align="center">
 <b>Built for SIH 2026</b><br>
 <a href="https://sih26106-email-forensics.onrender.com/dashboard">Live Demo</a> •
 <a href="https://github.com/SabarishR08/mailforensic-ai">GitHub</a> •
 <a href="https://colab.research.google.com/drive/1Rqz3TkPnmXebt8jz39oWvjM6Q-P4J-T1">Colab</a>
</p>

---

## License

[MIT](LICENSE) — © 2026 Sabarish R.
