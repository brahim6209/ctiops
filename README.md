# CTIOps

**A self-hosted Cyber Threat Intelligence platform that fuses ML-driven CVE/IOC scoring with DevSecOps pipelines — turning raw scan data into prioritized, actionable intelligence.**

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)
![scikit--learn](https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)
![STIX](https://img.shields.io/badge/STIX-2.1-00599C?style=flat-square)
![MISP](https://img.shields.io/badge/MISP-compatible-003366?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

CTIOps aggregates threat data from NVD, MISP, VirusTotal, OTX, GitHub and CI/CD pipelines, enriches it with real machine learning, normalizes it to STIX 2.1, and pushes it to OpenCTI — so security teams can see what actually matters instead of drowning in raw feeds.

## Why

Most CTI tooling either just aggregates feeds (no prioritization) or bolts on "AI" without real models. CTIOps trains its ML models on ground-truth data (CISA KEV as the exploited-in-the-wild label) instead of guessing, and treats DevSecOps signals (leaked secrets, CI/CD findings) as first-class threat intelligence alongside CVEs.

## What it does

- **CVE risk scoring** — Random Forest classifier trained on real CVE data, using CISA KEV membership as ground truth for "actively exploited"
- **Attack-type classification** — NLP pipeline (TF-IDF + Logistic Regression) classifies CVE descriptions into attack types (RCE, SSRF, auth bypass, SQLi, path traversal, supply chain, ...)
- **Kill-chain / MITRE ATT&CK mapping** — maps CVEs and DevSecOps findings onto ATT&CK techniques and kill-chain stages, and builds attack-path graphs
- **Patch prioritization via reinforcement learning** — Q-Learning agent recommends which CVE to patch first, balancing risk reduction against patch cost
- **DevSecOps as threat intel** — ingests leaked secrets (Gitleaks) and breach data (HaveIBeenPwned) as incidents, not just code-scanning noise
- **STIX 2.1 + TLP normalization** — every CVE/IOC/incident is normalized to STIX with a TLP marking before being pushed to OpenCTI
- **CI/CD native** — a report-watcher service and a Jenkins pipeline step (`send_cti.py`) feed pipeline findings straight into the platform

## Architecture

```
OSINT sources (NVD, MISP, OTX, VT, GitHub, CI/CD)
        │
        ▼
   Collectors  →  Enrichment (EPSS, CVSS, KEV)  →  ML scoring (RF / NLP / RL)
        │
        ▼
   STIX 2.1 + TLP normalization
        │
        ▼
   SQLite store  →  OpenCTI sync  →  REST API (Flask + FastAPI)  →  Dashboard
```

## Quickstart

```bash
git clone https://github.com/brahim6209/ctiops.git
cd ctiops
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# fill in VT_API_KEY, MISP_URL, MISP_KEY, NVD_API_KEY, OPENCTI_TOKEN

python api.py
# REST API on http://localhost:5000
```

Run the CI/CD report watcher in a second terminal:

```bash
source venv/bin/activate
python report_watcher.py
# watches /opt/ctiops/reports/ every 5s
```

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/stats` | Global statistics |
| `GET /api/v1/incidents` | All incidents |
| `GET /api/v1/cve` | CVEs enriched with NVD + EPSS |
| `GET /api/v1/ioc` | Collected IOCs |
| `GET /api/v1/misp/events` | MISP events |
| `GET /api/v1/devsecops/breach` | Gitleaks secrets + HIBP breach data |
| `POST /api/v1/devsecops/breach/check-all` | Check all secrets against HIBP |
| `GET /api/v1/devsecops/rl-patch` | RL-based patch recommendations |

## Jenkins integration

```bash
sudo cp scripts/send_cti.py /var/lib/jenkins/send_cti.py
```

Add to your `Jenkinsfile` as a final stage:

```groovy
sh 'python3 /var/lib/jenkins/send_cti.py'
```

Requires `APP_NAME`, `BUILD_NUMBER`, `APP_DIR` environment variables set by Jenkins.

## Stack

Python 3.12 · Flask + FastAPI · SQLite · scikit-learn (Random Forest, TF-IDF/Logistic Regression, Q-Learning) · STIX 2.1 · MISP · OpenCTI · NVD · VirusTotal · HaveIBeenPwned · EPSS

## License

MIT — see [LICENSE](LICENSE).
