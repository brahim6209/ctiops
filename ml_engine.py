"""
ml_engine.py — Vrai ML avec scikit-learn
Random Forest entraîné sur nos CVE réelles
Labels y=1 : CISA KEV (exploitées activement = ground truth)
Labels y=0 : CVE non exploitées
"""
import json, pickle, os, datetime
import numpy as np
from database import get_conn

# scikit-learn
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'ml_model.pkl')

# ── FEATURE EXTRACTION ────────────────────────────────────────────
def extract_features_from_db():
    """
    Extrait toutes les features depuis nos CVE en DB.
    X = features numériques + textuelles
    y = actively_exploited (CISA KEV = ground truth)
    """
    with get_conn() as c:
        cves = c.execute("""
            SELECT id, description, cvss_score, epss_score, epss_percentile,
                   has_exploit, actively_exploited, severity, keywords
            FROM cve
            WHERE epss_score IS NOT NULL
        """).fetchall()

    X_num = []   # features numériques
    X_text = []  # descriptions pour TF-IDF
    y = []       # labels CISA KEV
    ids = []

    for cve in cves:
        d = dict(cve)
        desc = (d.get('description') or '').lower()

        # Features numériques
        cvss = float(d.get('cvss_score') or 0)
        epss = float(d.get('epss_score') or 0)
        epss_pct = float(d.get('epss_percentile') or 0)
        has_exploit = int(d.get('has_exploit') or 0)

        # Features binaires depuis la description
        is_rce = int(any(k in desc for k in ['rce','remote code execution','execute arbitrary']))
        is_privesc = int(any(k in desc for k in ['privilege escalat','local privilege','root']))
        is_sqli = int(any(k in desc for k in ['sql injection','sql','sqli']))
        is_rfi = int(any(k in desc for k in ['file inclusion','path traversal','directory traversal']))
        is_auth = int(any(k in desc for k in ['authentication bypass','unauthenticated','no auth']))
        is_cred = int(any(k in desc for k in ['credential','password','secret','token','api key']))
        is_cloud = int(any(k in desc for k in ['aws','azure','gcp','cloud','s3','lambda','kubernetes','k8s']))
        is_cicd = int(any(k in desc for k in ['jenkins','github','gitlab','ci/cd','pipeline','build']))
        is_supply = int(any(k in desc for k in ['supply chain','dependency','package manager','npm','maven']))
        is_container = int(any(k in desc for k in ['docker','container','image','registry']))
        is_network = int(any(k in desc for k in ['remote','network','unauthenticated remote']))

        # Sévérité encodée
        sev_map = {'CRITICAL':4, 'HIGH':3, 'MEDIUM':2, 'LOW':1, 'NONE':0, 'UNKNOWN':0}
        sev_num = sev_map.get((d.get('severity') or 'UNKNOWN').upper(), 0)

        # EPSS buckets (features non-linéaires)
        epss_critical = int(epss >= 0.9)
        epss_high = int(epss >= 0.5)
        epss_medium = int(epss >= 0.1)

        # CVSS buckets
        cvss_critical = int(cvss >= 9.0)
        cvss_high = int(cvss >= 7.0)

        features = [
            cvss, epss, epss_pct, has_exploit,
            is_rce, is_privesc, is_sqli, is_rfi, is_auth,
            is_cred, is_cloud, is_cicd, is_supply, is_container, is_network,
            sev_num, epss_critical, epss_high, epss_medium,
            cvss_critical, cvss_high,
            # Interactions importantes
            epss * cvss,           # produit EPSS × CVSS
            has_exploit * epss,    # exploit public ET EPSS élevé
            is_rce * cvss_critical, # RCE ET critique
        ]

        X_num.append(features)
        X_text.append(desc[:500])  # max 500 chars pour TF-IDF
        y.append(int(d.get('actively_exploited') or 0))
        ids.append(d['id'])

    return np.array(X_num), X_text, np.array(y), ids

FEATURE_NAMES = [
    'cvss','epss','epss_pct','has_exploit',
    'is_rce','is_privesc','is_sqli','is_rfi','is_auth',
    'is_cred','is_cloud','is_cicd','is_supply','is_container','is_network',
    'sev_num','epss_critical','epss_high','epss_medium',
    'cvss_critical','cvss_high',
    'epss_x_cvss','exploit_x_epss','rce_x_critical'
]

# ── TRAINING ──────────────────────────────────────────────────────
def train_model():
    """
    Entraîne le Random Forest sur nos CVE réelles.
    Labels = CISA KEV (ground truth officiel CISA).
    """
    print("[ML] Extraction des features depuis la DB...")
    X_num, X_text, y, ids = extract_features_from_db()

    n_total = len(y)
    n_pos = y.sum()
    n_neg = n_total - n_pos
    print(f"[ML] Dataset: {n_total} CVE — {n_pos} exploitées (y=1) — {n_neg} non exploitées (y=0)")

    if n_pos < 5:
        print("[ML] Pas assez de labels positifs pour entraîner")
        return None

    # TF-IDF sur les descriptions
    print("[ML] Vectorisation TF-IDF des descriptions...")
    tfidf = TfidfVectorizer(
        max_features=100,
        ngram_range=(1,2),
        stop_words='english',
        min_df=2
    )
    X_tfidf = tfidf.fit_transform(X_text).toarray()

    # Combiner features numériques + TF-IDF
    X = np.hstack([X_num, X_tfidf])
    print(f"[ML] Features totales: {X.shape[1]} ({len(FEATURE_NAMES)} numériques + {X_tfidf.shape[1]} TF-IDF)")

    # Random Forest avec class_weight pour déséquilibre (19 pos vs 283 neg)
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=2,
        class_weight='balanced',  # compense le déséquilibre des classes
        random_state=42,
        n_jobs=-1
    )

    # Cross-validation pour évaluer
    print("[ML] Cross-validation (5-fold)...")
    cv_scores = cross_val_score(rf, X, y, cv=5, scoring='roc_auc')
    print(f"[ML] AUC-ROC: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

    # Entraînement final sur toutes les données
    rf.fit(X, y)

    # Feature importance
    importances = rf.feature_importances_[:len(FEATURE_NAMES)]
    top_features = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)[:5]
    print("[ML] Top 5 features importantes:")
    for fname, imp in top_features:
        print(f"  {fname}: {imp:.3f}")

    # Sauvegarder le modèle
    model_data = {
        'rf': rf,
        'tfidf': tfidf,
        'feature_names': FEATURE_NAMES,
        'n_features_num': len(FEATURE_NAMES),
        'auc_roc': cv_scores.mean(),
        'n_train': n_total,
        'n_positive': int(n_pos),
        'trained_at': datetime.datetime.now().isoformat(),
        'version': '2.0'
    }
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model_data, f)
    print(f"[ML] Modèle sauvegardé: {MODEL_PATH}")
    return model_data

# ── PREDICTION ────────────────────────────────────────────────────
_model_cache = None

def load_model():
    global _model_cache
    if _model_cache:
        return _model_cache
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            _model_cache = pickle.load(f)
        return _model_cache
    return None

def predict_exploitation(cve_data: dict) -> dict:
    """
    Prédit la probabilité d'exploitation d'une CVE.
    Utilise le Random Forest entraîné sur CISA KEV.
    """
    model = load_model()
    if not model:
        # Fallback vers scoring pondéré si pas de modèle
        return _fallback_score(cve_data)

    desc = (cve_data.get('description') or '').lower()
    cvss = float(cve_data.get('cvss_score') or 0)
    epss = float(cve_data.get('epss_score') or 0)
    epss_pct = float(cve_data.get('epss_percentile') or 0)
    has_exploit = int(cve_data.get('has_exploit') or 0)

    is_rce = int(any(k in desc for k in ['rce','remote code execution','execute arbitrary']))
    is_privesc = int(any(k in desc for k in ['privilege escalat','local privilege','root']))
    is_sqli = int(any(k in desc for k in ['sql injection','sqli']))
    is_rfi = int(any(k in desc for k in ['file inclusion','path traversal']))
    is_auth = int(any(k in desc for k in ['authentication bypass','unauthenticated']))
    is_cred = int(any(k in desc for k in ['credential','password','secret','token']))
    is_cloud = int(any(k in desc for k in ['aws','azure','gcp','cloud','kubernetes']))
    is_cicd = int(any(k in desc for k in ['jenkins','github','gitlab','pipeline']))
    is_supply = int(any(k in desc for k in ['supply chain','dependency','npm','maven']))
    is_container = int(any(k in desc for k in ['docker','container','image']))
    is_network = int(any(k in desc for k in ['remote','unauthenticated remote']))
    sev_map = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'NONE':0,'UNKNOWN':0}
    sev_num = sev_map.get((cve_data.get('severity') or 'UNKNOWN').upper(), 0)

    X_num = np.array([[
        cvss, epss, epss_pct, has_exploit,
        is_rce, is_privesc, is_sqli, is_rfi, is_auth,
        is_cred, is_cloud, is_cicd, is_supply, is_container, is_network,
        sev_num, int(epss>=0.9), int(epss>=0.5), int(epss>=0.1),
        int(cvss>=9.0), int(cvss>=7.0),
        epss*cvss, has_exploit*epss, is_rce*int(cvss>=9.0)
    ]])

    X_tfidf = model['tfidf'].transform([desc[:500]]).toarray()
    X = np.hstack([X_num, X_tfidf])

    prob = model['rf'].predict_proba(X)[0][1]  # probabilité classe 1 (exploitée)
    prob_pct = round(prob * 100, 1)

    # Jours avant exploitation probable
    if cve_data.get('actively_exploited'): days = 0
    elif has_exploit and prob_pct > 80: days = 3
    elif prob_pct > 70: days = 7
    elif prob_pct > 50: days = 30
    else: days = 90

    return {
        'probability': prob_pct,
        'days_to_exploit': days,
        'patch_priority': ('P0-IMMEDIATE' if days==0 else 'P1-URGENT' if days<=7
                          else 'P2-PLANNED' if days<=30 else 'P3-MONITOR'),
        'model': 'RandomForest',
        'model_auc': round(model.get('auc_roc', 0), 3),
        'trained_on': model.get('n_train', 0),
    }

def _fallback_score(cve_data):
    """Fallback scoring pondéré si pas de modèle entraîné."""
    epss = float(cve_data.get('epss_score') or 0)
    cvss = float(cve_data.get('cvss_score') or 0)
    has_exploit = int(cve_data.get('has_exploit') or 0)
    active = int(cve_data.get('actively_exploited') or 0)
    score = epss*40 + (cvss/10)*20 + has_exploit*15 + active*20
    return {'probability': min(99, round(score,1)), 'model': 'fallback_weighted'}

# ── AUTO-RETRAIN ──────────────────────────────────────────────────
def should_retrain():
    """Vérifie si le modèle doit être réentraîné."""
    if not os.path.exists(MODEL_PATH):
        return True, "Modèle inexistant"
    model = load_model()
    if not model:
        return True, "Modèle corrompu"
    # Réentraîner si nouvelles CVE depuis dernier entraînement
    trained_at = model.get('trained_at','')
    with get_conn() as c:
        n_current = c.execute('SELECT COUNT(*) FROM cve WHERE epss_score IS NOT NULL').fetchone()[0]
    if n_current > model.get('n_train', 0) + 10:
        return True, f"Nouvelles données: {n_current} vs {model.get('n_train',0)} au dernier entraînement"
    return False, "Modèle à jour"

def get_model_info():
    """Retourne les infos du modèle actuel."""
    model = load_model()
    if not model:
        return {'status': 'not_trained', 'message': 'Modèle non entraîné'}
    retrain_needed, reason = should_retrain()
    return {
        'status': 'ready',
        'model_type': 'RandomForestClassifier',
        'auc_roc': round(model.get('auc_roc', 0), 3),
        'trained_on': model.get('n_train', 0),
        'n_positive': model.get('n_positive', 0),
        'trained_at': model.get('trained_at', ''),
        'version': model.get('version', ''),
        'retrain_needed': retrain_needed,
        'retrain_reason': reason,
    }
