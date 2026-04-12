"""
Random Forest — Prédiction probabilité d'exploitation par build.
Features : CVSS, EPSS, reality_score, nb_secrets, nb_cve_kev,
           nb_exploits, nb_critical, attack_type_encoded, scanner_count
Label    : probability_class (LOW/MEDIUM/HIGH/CRITICAL)
"""
import json
import numpy as np
from database import get_conn

# ── Feature extraction ────────────────────────────────────────
def extract_build_features(build: str) -> dict:
    """Extraire les features numériques d'un build."""
    with get_conn() as c:
        # Incidents du build
        incs = c.execute("""
            SELECT source, severity, mitre_id,
                   json_extract(details,'$.cve_id') as cve_id,
                   json_extract(details,'$.entropy') as entropy,
                   json_extract(details,'$.rule_id') as rule_id
            FROM incident
            WHERE json_extract(details,'$.build')=?
        """, (str(build),)).fetchall()

        # CVE enrichies du build
        cves = c.execute("""
            SELECT c.cvss_score, c.epss_score, c.reality_score,
                   c.actively_exploited, c.has_exploit, c.attack_type
            FROM incident i
            LEFT JOIN cve c ON json_extract(i.details,'$.cve_id') = c.id
            WHERE i.source IN ('trivy','owasp')
            AND json_extract(i.details,'$.build')=?
            AND c.id IS NOT NULL
        """, (str(build),)).fetchall()

    incs = [dict(i) for i in incs]
    cves = [dict(c) for c in cves]

    # Grouper par scanner
    scanners = set(i['source'] for i in incs)
    secrets  = [i for i in incs if i['source'] == 'gitleaks']

    # Features CVE
    cvss_scores   = [float(c['cvss_score'] or 0)   for c in cves]
    epss_scores   = [float(c['epss_score'] or 0)    for c in cves]
    reality_scores= [float(c['reality_score'] or 0) for c in cves]
    attack_types  = [c['attack_type'] or 'UNKNOWN'  for c in cves]

    # Encodage attack types
    attack_enc = {
        'RCE':15, 'SSRF':12, 'AUTH_BYPASS':13, 'PRIVESC':11,
        'SQLI':10, 'PATH_TRAVERSAL':9, 'SUPPLY_CHAIN':8,
        'INFO_DISCLOSURE':6, 'CLOUD_SPECIFIC':7, 'DoS':5,
        'XSS':4, 'UNKNOWN':0
    }
    top_attack = max(attack_types, key=lambda x: attack_enc.get(x,0)) \
                 if attack_types else 'UNKNOWN'

    features = {
        # CVE features
        'nb_cve'          : len(cves),
        'nb_critical'     : sum(1 for i in incs if i['severity']=='CRITICAL'),
        'nb_high'         : sum(1 for i in incs if i['severity']=='HIGH'),
        'nb_kev'          : sum(1 for c in cves if c['actively_exploited']),
        'nb_exploit'      : sum(1 for c in cves if c['has_exploit']),

        # Scores CVE
        'max_cvss'        : max(cvss_scores, default=0),
        'avg_cvss'        : np.mean(cvss_scores) if cvss_scores else 0,
        'max_epss'        : max(epss_scores, default=0),
        'avg_epss'        : np.mean(epss_scores) if epss_scores else 0,
        'max_reality'     : max(reality_scores, default=0),
        'avg_reality'     : np.mean(reality_scores) if reality_scores else 0,

        # Secrets features
        'nb_secrets'      : len(secrets),
        'nb_secrets_crit' : sum(1 for s in secrets if s['severity']=='CRITICAL'),
        'max_entropy'     : max((float(s['entropy'] or 0) for s in secrets), default=0),

        # Pipeline features
        'nb_scanners'     : len(scanners),
        'has_gitleaks'    : int('gitleaks' in scanners),
        'has_trivy'       : int('trivy' in scanners),
        'has_owasp'       : int('owasp' in scanners),
        'has_sonarqube'   : int('sonarqube' in scanners),

        # Attack type encodé
        'top_attack_score': attack_enc.get(top_attack, 0),
    }
    return features

# ── Génération du dataset d'entraînement ──────────────────────
def generate_training_data():
    """
    Générer des données d'entraînement synthétiques mais réalistes.
    Basé sur les règles CISA/EPSS/CVSS documentées.
    Label = probabilité d'exploitation (0-100)
    """
    import random
    random.seed(42)
    np.random.seed(42)

    X, y = [], []

    # Scénarios CRITICAL (prob 75-99)
    for _ in range(120):
        nb_kev     = random.randint(1, 10)
        nb_exploit = random.randint(1, 15)
        max_epss   = random.uniform(0.7, 1.0)
        max_cvss   = random.uniform(8.5, 10.0)
        nb_secrets = random.randint(1, 15)
        X.append([
            random.randint(20, 80), # nb_cve
            random.randint(10, 40), # nb_critical
            random.randint(5, 20),  # nb_high
            nb_kev,                 # nb_kev
            nb_exploit,             # nb_exploit
            max_cvss,               # max_cvss
            random.uniform(7, 9.5), # avg_cvss
            max_epss,               # max_epss
            random.uniform(0.4, max_epss), # avg_epss
            random.uniform(70, 100),# max_reality
            random.uniform(50, 85), # avg_reality
            nb_secrets,             # nb_secrets
            random.randint(1, nb_secrets), # nb_secrets_crit
            random.uniform(4.5, 7.5),     # max_entropy
            random.randint(2, 4),   # nb_scanners
            1, 1,                   # has_gitleaks, has_trivy
            random.randint(0,1),    # has_owasp
            random.randint(0,1),    # has_sonarqube
            15,                     # top_attack_score (RCE)
        ])
        y.append(random.randint(75, 99))

    # Scénarios HIGH (prob 45-74)
    for _ in range(120):
        nb_kev   = random.randint(0, 3)
        max_epss = random.uniform(0.3, 0.7)
        max_cvss = random.uniform(7.0, 9.0)
        X.append([
            random.randint(10, 50),
            random.randint(3, 15),
            random.randint(3, 15),
            nb_kev,
            random.randint(0, 5),
            max_cvss,
            random.uniform(5, 8),
            max_epss,
            random.uniform(0.1, max_epss),
            random.uniform(40, 75),
            random.uniform(25, 55),
            random.randint(0, 8),
            random.randint(0, 4),
            random.uniform(3.0, 5.5),
            random.randint(1, 3),
            random.randint(0,1), 1,
            random.randint(0,1),
            random.randint(0,1),
            random.choice([12, 13, 11, 10]),
        ])
        y.append(random.randint(45, 74))

    # Scénarios MEDIUM (prob 20-44)
    for _ in range(100):
        max_epss = random.uniform(0.05, 0.3)
        X.append([
            random.randint(5, 30),
            random.randint(0, 5),
            random.randint(1, 10),
            0,
            random.randint(0, 2),
            random.uniform(5.0, 7.5),
            random.uniform(3, 6),
            max_epss,
            random.uniform(0.01, max_epss),
            random.uniform(15, 45),
            random.uniform(8, 30),
            random.randint(0, 3),
            0,
            random.uniform(1.5, 3.5),
            random.randint(1, 2),
            0, random.randint(0,1),
            random.randint(0,1), 0,
            random.choice([9, 8, 7, 6, 0]),
        ])
        y.append(random.randint(20, 44))

    # Scénarios LOW (prob 0-19)
    for _ in range(80):
        X.append([
            random.randint(0, 10),
            0,
            random.randint(0, 3),
            0, 0,
            random.uniform(0, 5.5),
            random.uniform(0, 4),
            random.uniform(0, 0.05),
            random.uniform(0, 0.03),
            random.uniform(0, 20),
            random.uniform(0, 12),
            0, 0,
            random.uniform(0, 2.0),
            1,
            0, random.randint(0,1), 0, 0,
            random.choice([0, 4, 5]),
        ])
        y.append(random.randint(0, 19))

    return np.array(X, dtype=float), np.array(y, dtype=float)

# ── Entraînement du modèle ────────────────────────────────────
_model = None
_model_metrics = {
    "mae": None, "r2": None, "n_estimators": 200,
    "trained_at": None, "n_samples": 0, "top_features": []
}
_feature_names = [
    'nb_cve','nb_critical','nb_high','nb_kev','nb_exploit',
    'max_cvss','avg_cvss','max_epss','avg_epss',
    'max_reality','avg_reality',
    'nb_secrets','nb_secrets_crit','max_entropy',
    'nb_scanners','has_gitleaks','has_trivy','has_owasp','has_sonarqube',
    'top_attack_score'
]

def get_metrics():
    """Retourne les métriques du modèle ML."""
    return dict(_model_metrics)

def get_model():
    global _model
    if _model is not None:
        return _model

    try:
        from sklearn.ensemble import RandomForestRegressor
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import mean_absolute_error, r2_score

        print("[ML-RF] Entraînement Random Forest attack predictor...")
        X, y = generate_training_data()
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        rf = RandomForestRegressor(
            n_estimators=200,
            max_depth=8,
            min_samples_split=4,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1
        )
        rf.fit(X_train, y_train)

        # Évaluation
        y_pred = rf.predict(X_test)
        mae  = mean_absolute_error(y_test, y_pred)
        r2   = r2_score(y_test, y_pred)
        print(f"[ML-RF] MAE: {mae:.2f} | R²: {r2:.3f} | Trees: 200")
        import datetime
        _model_metrics["mae"] = round(mae, 3)
        _model_metrics["r2"] = round(r2, 3)
        _model_metrics["trained_at"] = datetime.datetime.utcnow().isoformat()
        _model_metrics["n_samples"] = len(X)
        _model_metrics["top_features"] = [(f, round(float(i), 3)) for f, i in
            zip(_feature_names, rf.feature_importances_)][:5] if hasattr(rf, 'feature_importances_') else []

        # Feature importance top 5
        importances = sorted(
            zip(_feature_names, rf.feature_importances_),
            key=lambda x: -x[1]
        )[:5]
        print(f"[ML-RF] Top features: {[(n, round(v,3)) for n,v in importances]}")

        _model = rf
        return _model

    except ImportError:
        print("[ML-RF] sklearn non disponible — fallback heuristique")
        return None

def predict_exploitation_probability(features: dict) -> dict:
    """
    Prédire la probabilité d'exploitation avec Random Forest.
    Retourne prob ML + feature importance pour ce build.
    """
    model = get_model()

    # Construire le vecteur de features
    X = np.array([[
        features.get(f, 0) for f in _feature_names
    ]], dtype=float)

    if model is not None:
        prob_rf = float(np.clip(model.predict(X)[0], 0, 100))

        # Feature importance pour ce build spécifique
        importances = sorted(
            zip(_feature_names, model.feature_importances_),
            key=lambda x: -x[1]
        )[:5]

        # Quelle feature contribue le plus pour ce build
        contributing = []
        for fname, fimp in importances[:3]:
            val = features.get(fname, 0)
            if val > 0:
                contributing.append({
                    "feature": fname,
                    "value": round(float(val), 3),
                    "importance": round(float(fimp), 3)
                })

        return {
            "probability": round(prob_rf, 1),
            "model": "RandomForest",
            "n_estimators": 200,
            "contributing_features": contributing,
            "confidence": "HIGH" if features.get('nb_kev',0) > 0 else "MEDIUM"
        }
    else:
        # Fallback heuristique si sklearn absent
        prob = min(97,
            features.get('nb_kev',0) * 20 +
            features.get('nb_exploit',0) * 8 +
            int(features.get('max_epss',0) * 40) +
            int(features.get('max_cvss',0) * 2) +
            features.get('nb_secrets_crit',0) * 10
        )
        return {
            "probability": float(prob),
            "model": "heuristic_fallback",
            "contributing_features": [],
            "confidence": "LOW"
        }
