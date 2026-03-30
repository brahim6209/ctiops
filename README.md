# CTI Cloud-Native Platform

Plateforme de Cyber Threat Intelligence pour la sécurité cloud-native.
Projet Master Bac+6 CTI 2025-2026.

## Architecture
- **NVD API** — Collecte CVE cloud en temps réel
- **GitHub Actions Webhook** — Détection incidents CI/CD
- **VirusTotal** — Enrichissement IOC
- **MISP Docker** — Plateforme CTI professionnelle
- **ML Models** — 4 modèles scikit-learn (Random Forest, Logistic Regression, Isolation Forest, K-Means)
- **Dashboard Flask** — Interface interactive avec export PDF/JSON/CSV

## Lancement
```bash
cd ~/cti && source venv/bin/activate
python dashboard.py
```

## Classification : TLP:AMBER
