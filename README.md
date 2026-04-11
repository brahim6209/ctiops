
# CTIOps — Backend (Flask + Python)

Plateforme de cybersécurité intelligente : IOC, CVE, DevSecOps, ML, RL.

## Stack
- Python 3.12, Flask, SQLite
- scikit-learn (Random Forest, Q-Learning)
- MISP, VirusTotal, NVD, HIBP, EPSS

## Installation

```bash
git clone https://github.com/brahim6209/ctiops.git
cd ctiops
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

```bash
# Copier et éditer la config
cp config.example.py config.py
# Renseigner : VT_API_KEY, MISP_URL, MISP_KEY, NVD_API_KEY
```

## Démarrage

```bash
source venv/bin/activate
python api.py
# API disponible sur http://localhost:5000
```

## Report Watcher (CI/CD listener)

```bash
# Dans un second terminal
source venv/bin/activate
python report_watcher.py
# Surveille /opt/ctiops/reports/ toutes les 5s
```

## Endpoints principaux

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/stats` | Statistiques globales |
| `GET /api/v1/incidents` | Tous les incidents |
| `GET /api/v1/cve` | CVE enrichies NVD+EPSS |
| `GET /api/v1/ioc` | IOC collectés |
| `GET /api/v1/misp/events` | Événements MISP |
| `GET /api/v1/devsecops/breach` | Secrets GitLeaks + HIBP |
| `POST /api/v1/devsecops/breach/check-all` | Vérifier tous les secrets HIBP |
| `GET /api/v1/devsecops/rl-patch` | RL Patch Recommender |

## Jenkins Integration

```bash
# Copier send_cti.py sur le serveur Jenkins
sudo cp scripts/send_cti.py /var/lib/jenkins/send_cti.py

# Dans le Jenkinsfile, ajouter en stage final :
sh 'python3 /var/lib/jenkins/send_cti.py'

# Variables d'environnement Jenkins requises :
# APP_NAME   → nom du projet (ex: toptrucks)
# BUILD_NUMBER → numéro de build Jenkins
# APP_DIR    → chemin workspace Jenkins
```
