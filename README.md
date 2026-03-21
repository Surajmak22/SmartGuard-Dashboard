---
title: SmartGuard AI
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# SmartGuard AI – Advanced Threat Analysis Center

SmartGuard AI is a production-grade, defense-in-depth file upload and malware detection system. Unlike standard systems that rely solely on signature-based antivirus or basic file-extension checks, SmartGuard AI implements a multi-layered security architecture (Validation → Antivirus → Format Analysis → Heuristic Analysis → Machine Learning → Content Disarm & Reconstruction) optimized for high recall and zero-trust file ingestion.

## 🛡️ Core Features

- **Multi-Layered Detection Engine:**
  - **Layer 1: Signature & Static Analysis:** Checks SHA-256 against known threat databases, verifies MIME types against declared extensions, and detects double extensions (`.pdf.exe`).
  - **Layer 2: Format-Specific Deep Parsers:** Dedicated parsers for PDF, Image (JPEG/PNG), DOCX, and EXE files to identify polyglot files, embedded payloads, malicious macros, and obfuscated API imports.
  - **Layer 3: Heuristics Engine:** Scans against 100+ YARA-like regex patterns across 10 threat categories (Ransomware, Command & Control, Privilege Escalation, Credential Theft, etc.).
  - **Layer 4: Machine Learning Ensembles:** Highly accurate format-specific XGBoost and Random Forest models trained on byte-level entropy and structural features to catch Zero-Day threats.
- **Content Disarm and Reconstruction (CDR):** Actively neutralizes threats instead of just blocking them. Strips `/JavaScript` from PDFs, removes `vbaProject.bin` from DOCX, strips EXIF data from images, and drops executable payloads from ZIP archives while mitigating ZipSlip directory traversal attacks.
- **Autonomous MLOps Pipeline:** Features a continuous learning loop. Endpoints allow SOC analysts to report missed threats which are automatically ingested, hashed, and processed. The `auto_improve.py` daemon uses Optuna for hyperparameter tuning and MLflow for tracking, atomically hot-swapping models that drop below a 90% recall threshold.
- **Production API:** A highly scalable FastAPI backend offering endpoints for single and batch file scanning, historical audit logs, aggressive sanitization, and system health checks.

## 🏗️ Architecture Flow

```text
Upload File
    │
    ▼
[Validation] MIME & Extension Integrity
    │
    ▼
[Antivirus] ClamAV (4-Tier Fallback: TCP, Unix Socket, Scanner CLI, EICAR)
    │
    ▼
[Format Analysis] Deep parsing (PDF, Image, DOCX, EXE, ZIP)
    │
    ▼
[Heuristics & ML] 100+ Rule Patterns + Format-Specific XGBoost Classifiers
    │
    ▼
[Sanitization (CDR)] Destructive cleaning of risky but salvageable files
    │
    ▼
Decision (STORE / SANITIZE / QUARANTINE / REJECT)
```

## 🚀 Installation & Setup

### Prerequisites
- Python 3.9+
- ClamAV running locally (`clamd` process on port 3310 or Unix socket, or `clamscan` available in `PATH`).

### 1. Clone & Install
```bash
git clone https://github.com/Surajmak22/SmartGuard-Dashboard.git
cd SmartGuard-Dashboard
python -m venv venv
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

### 2. Run the FastAPI Backend
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
Access the comprehensive OpenAPI documentation at `http://localhost:8000/api/docs`.

### 3. Run the Legacy Streamlit Portal
```bash
streamlit run src/dashboard/main_app.py
```

## 🧠 Continuous Learning & MLOps Automation

SmartGuard AI features an automated pipeline powered by **MLflow**, **PyArrow Parquet**, and **Optuna**.

- **Extracting Features:** `python scripts/mlops/feature_extractor.py` dumps high-speed parallelized byte features into `.parquet` files utilizing all CPU cores.
- **Training Custom Models:** `python scripts/mlops/train_models.py` loops through the datasets, trains ensembles, and tracks metrics seamlessly via MLflow SQLite stores.
- **Auto-Improvement:** `python scripts/mlops/auto_improve.py` dynamically triggers hyperparameter sweeps whenever recall dips below optimal thresholds, aggressively fixing weak models.

*To submit a false negative or false positive, use the `POST /api/v1/feedback/report` endpoint.*

## 🔒 Safety Notice
When updating or appending to the custom internal datasets, this automated infrastructure is specifically programmed to avoid autonomously downloading live, raw weaponized malware payloads natively to a host OS (e.g., from generic automated VirusShare scripts). It pulls safe mathematical feature sets (like EMBER 2018). Raw malware ingestion should be provided manually by SOC teams running entirely sandboxed environments.
