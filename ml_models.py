"""ml_models.py — 4 modèles ML CTI (Random Forest, Logistic Regression, Isolation Forest, K-Means)"""
import os, joblib, numpy as np, random
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

random.seed(42); np.random.seed(42)
MODELS_DIR = os.path.join(os.path.dirname(__file__), "data", "models")
os.makedirs(MODELS_DIR, exist_ok=True)

EVENT_MAP    = {"secret_exposed":0,"workflow_injected":1,"priv_escalation":2,
                "image_unsigned":3,"suspicious_push":4,"job_failed_repeat":5,"unknown":6}
SEV_LABELS   = {0:"LOW",1:"MEDIUM",2:"HIGH",3:"CRITICAL"}
CLUSTER_NAMES= {0:"Injection & RCE",1:"Credentials & secrets",
                2:"Privilege escalation",3:"Supply chain",4:"Misconfiguration"}

# ── DATA SYNTHÉTIQUE ─────────────────────────────────────────────────────────

def _ioc_data(n=500):
    X, y = [], []
    for _ in range(n):
        mal = random.random() > 0.5
        X.append([random.uniform(50,100) if mal else random.uniform(0,20),
                  random.randint(10,70) if mal else random.randint(0,5),
                  random.randint(60,75), random.randint(0,3)])
        y.append(int(mal))
    return np.array(X), np.array(y)

def _incident_data(n=400):
    X, y = [], []
    base = [3,3,2,2,1,1,0]
    for _ in range(n):
        ev   = random.randint(0,6)
        hour = random.randint(0,23)
        X.append([ev, random.randint(0,2), hour, int(hour<6)])
        y.append(min(3, base[ev] + (1 if hour<6 else 0)))
    return np.array(X), np.array(y)

def _cicd_logs(n=300):
    X, y = [], []
    for _ in range(n):
        a = random.random() > 0.85
        X.append([random.uniform(0.1,5) if a else random.uniform(30,300),
                  random.uniform(0.7,1) if a else random.uniform(0,0.2),
                  random.randint(1,3)   if a else random.randint(5,20),
                  random.choice([2,3,4]) if a else random.randint(8,20)])
        y.append(int(a))
    return np.array(X), np.array(y)

CVE_DESCS = [
    "Remote code execution in Kubernetes API server",
    "AWS IAM privilege escalation via role policy",
    "Docker container escape vulnerability",
    "Azure injection in cloud web application",
    "GCP service account key exposure via CI/CD",
    "S3 bucket public access misconfiguration",
    "Lambda serverless function injection",
    "GitHub Actions secret leak in workflow",
    "GitLab CI runner privilege escalation",
    "OpenID Connect token forgery in IAM",
] * 20

# ── ENTRAÎNEMENT ─────────────────────────────────────────────────────────────

def train_ioc_scorer():
    print("[ML] Entraînement IOC Scorer (Random Forest)...")
    X, y = _ioc_data()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
    m = RandomForestClassifier(n_estimators=100, random_state=42).fit(Xtr, ytr)
    print(f"[ML] IOC Scorer      — Accuracy: {accuracy_score(yte, m.predict(Xte)):.2%}")
    joblib.dump(m, f"{MODELS_DIR}/ioc_scorer.pkl")
    return m

def train_severity_predictor():
    print("[ML] Entraînement Severity Predictor (Logistic Regression)...")
    X, y = _incident_data()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
    p = Pipeline([("s", StandardScaler()), ("c", LogisticRegression(max_iter=1000))]).fit(Xtr, ytr)
    print(f"[ML] Severity Pred.  — Accuracy: {accuracy_score(yte, p.predict(Xte)):.2%}")
    joblib.dump(p, f"{MODELS_DIR}/severity_predictor.pkl")
    return p

def train_anomaly_detector():
    print("[ML] Entraînement Anomaly Detector (Isolation Forest)...")
    X, y = _cicd_logs()
    normal = X[y == 0]
    m = IsolationForest(n_estimators=100, contamination=0.1, random_state=42).fit(normal)
    print(f"[ML] Anomaly Detect. — Entraîné sur {len(normal)} logs normaux")
    joblib.dump(m, f"{MODELS_DIR}/anomaly_detector.pkl")
    return m

def train_cve_clustering():
    print("[ML] Entraînement CVE Clustering (K-Means + TF-IDF)...")
    vec = TfidfVectorizer(max_features=100, stop_words="english", ngram_range=(1,2))
    X   = vec.fit_transform(CVE_DESCS)
    km  = KMeans(n_clusters=5, random_state=42, n_init=10).fit(X)
    print(f"[ML] CVE Clustering  — 5 clusters OK")
    joblib.dump(km,  f"{MODELS_DIR}/cve_clustering.pkl")
    joblib.dump(vec, f"{MODELS_DIR}/tfidf_vectorizer.pkl")
    return km, vec

def train_all():
    print("\n" + "="*45)
    print("  Entraînement de tous les modèles ML")
    print("="*45)
    train_ioc_scorer()
    train_severity_predictor()
    train_anomaly_detector()
    train_cve_clustering()
    print("\n[ML] Tous les modèles sont prêts !")

# ── PRÉDICTIONS ───────────────────────────────────────────────────────────────

def score_ioc(value, ioc_type, vt_score, malicious_count, total_engines) -> dict:
    path  = f"{MODELS_DIR}/ioc_scorer.pkl"
    model = joblib.load(path) if os.path.exists(path) else train_ioc_scorer()
    X     = np.array([[vt_score, malicious_count, total_engines, {"ip":0,"domain":1,"hash":2,"url":3}.get(ioc_type,3)]])
    pred  = model.predict(X)[0]
    conf  = round(float(max(model.predict_proba(X)[0])) * 100, 1)
    return {"is_malicious": bool(pred), "confidence": conf, "label": "MALVEILLANT" if pred else "BÉNIN"}

def predict_severity(event_type, source="github_actions", triggered_at=None) -> dict:
    from datetime import datetime, timezone
    path  = f"{MODELS_DIR}/severity_predictor.pkl"
    model = joblib.load(path) if os.path.exists(path) else train_severity_predictor()
    try:
        dt   = datetime.fromisoformat(triggered_at) if triggered_at else datetime.now(timezone.utc)
        hour = dt.hour
    except Exception:
        hour = 12
    X    = np.array([[EVENT_MAP.get(event_type,6), 0, hour, int(hour<6)]])
    pred = model.predict(X)[0]
    conf = round(float(max(model.predict_proba(X)[0])) * 100, 1)
    return {"severity": SEV_LABELS[pred], "confidence": conf}

def detect_anomaly(duration_s, fail_rate, nb_steps, hour) -> dict:
    path  = f"{MODELS_DIR}/anomaly_detector.pkl"
    model = joblib.load(path) if os.path.exists(path) else train_anomaly_detector()
    X     = np.array([[duration_s, fail_rate, nb_steps, hour]])
    pred  = model.predict(X)[0]
    score = model.decision_function(X)[0]
    anom_score = round(max(0, min(100, (-score)*50+50)), 1)
    return {"is_anomaly": pred==-1, "anomaly_score": anom_score, "label": "ANOMALIE" if pred==-1 else "NORMAL"}

def cluster_cve(description) -> dict:
    mp, vp = f"{MODELS_DIR}/cve_clustering.pkl", f"{MODELS_DIR}/tfidf_vectorizer.pkl"
    if os.path.exists(mp) and os.path.exists(vp):
        km, vec = joblib.load(mp), joblib.load(vp)
    else:
        km, vec = train_cve_clustering()
    cid = int(km.predict(vec.transform([description]))[0])
    return {"cluster_id": cid, "cluster_name": CLUSTER_NAMES.get(cid, f"Cluster {cid}")}

if __name__ == "__main__":
    train_all()
    print("\n--- Tests ---")
    print(score_ioc("1.2.3.4","ip",80,55,70))
    print(predict_severity("secret_exposed", triggered_at="2024-03-15T03:00:00"))
    print(detect_anomaly(0.5, 1.0, 1, 3))
    print(cluster_cve("Remote code execution in Kubernetes API server"))
