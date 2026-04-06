"""
nlp_classifier.py — CVE Attack Type Classifier
NLP Pipeline: TF-IDF + Logistic Regression
Entraîné sur les descriptions CVE de la DB locale

Usage:
    # Entraîner et sauvegarder le modèle
    python3 nlp_classifier.py train

    # Classifier une description
    python3 nlp_classifier.py predict "remote code execution via buffer overflow"

    # Re-classifier tous les CVE UNKNOWN en DB
    python3 nlp_classifier.py reclassify
"""

import sys
import os
import json
import sqlite3
import re
import joblib
import numpy as np

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "data", "cti.db")
MODEL_PATH = os.path.join(BASE_DIR, "data", "nlp_cve_classifier.pkl")

# ─── Labels ───────────────────────────────────────────────────────────────────
# Classes cibles — doivent correspondre aux valeurs dans la DB
TARGET_CLASSES = [
    "RCE", "SSRF", "SQLI", "XSS", "XXE",
    "PRIVESC", "AUTH_BYPASS", "PATH_TRAVERSAL",
    "DOS", "INFO_DISCLOSURE", "SUPPLY_CHAIN",
    "CLOUD_SPECIFIC", "CONTAINER_ESCAPE", "IDOR", "UNKNOWN"
]

# ─── Text preprocessing ───────────────────────────────────────────────────────
def preprocess(text: str) -> str:
    """Nettoyer et normaliser la description CVE."""
    if not text:
        return ""
    # Minuscules
    text = text.lower()
    # Supprimer les versions (1.2.3, v1.2)
    text = re.sub(r'\bv?\d+\.\d+[\.\d]*\b', 'VERSION', text)
    # Supprimer les CVE IDs
    text = re.sub(r'cve-\d{4}-\d+', 'CVEID', text)
    # Normaliser la ponctuation
    text = re.sub(r'[^\w\s]', ' ', text)
    # Supprimer les espaces multiples
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# ─── Load data from DB ────────────────────────────────────────────────────────
def load_training_data():
    """Charger les CVE avec attack_type connu depuis la DB."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute("""
        SELECT description, attack_type 
        FROM cve 
        WHERE description IS NOT NULL 
          AND description != ''
          AND attack_type IS NOT NULL
          AND attack_type != ''
    """).fetchall()
    conn.close()
    
    texts  = []
    labels = []
    
    for row in rows:
        desc  = preprocess(row["description"])
        label = row["attack_type"]
        if desc and label in TARGET_CLASSES:
            texts.append(desc)
            labels.append(label)
    
    return texts, labels

# ─── Train ────────────────────────────────────────────────────────────────────
def train():
    """Entraîner le modèle NLP et sauvegarder."""
    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import LabelEncoder
    import warnings
    warnings.filterwarnings('ignore')

    print("=" * 55)
    print("CTI Platform — CVE NLP Classifier Training")
    print("=" * 55)

    # ── 1. Charger les données ──
    print("\n[1/4] Chargement des données...")
    texts, labels = load_training_data()
    print(f"      → {len(texts)} CVE chargées")
    
    # Distribution des classes
    from collections import Counter
    dist = Counter(labels)
    print("      → Distribution:")
    for cls, count in sorted(dist.items(), key=lambda x: -x[1]):
        pct = count / len(labels) * 100
        bar = "█" * int(pct / 2)
        print(f"         {cls:<20} {count:>4} ({pct:5.1f}%) {bar}")

    # ── 2. Split train/test ──
    print("\n[2/4] Split train/test (80/20)...")
    # Exclure les classes trop rares pour le stratify (< 5 exemples)
    from collections import Counter
    counts = Counter(labels)
    min_samples = 5
    filtered = [(t, l) for t, l in zip(texts, labels) if counts[l] >= min_samples]
    texts_f  = [x[0] for x in filtered]
    labels_f = [x[1] for x in filtered]
    removed  = len(texts) - len(texts_f)
    if removed > 0:
        rare = [c for c, n in counts.items() if n < min_samples]
        print(f"      → {removed} CVE exclus (classes rares < {min_samples}: {rare})")

    X_train, X_test, y_train, y_test = train_test_split(
        texts_f, labels_f,
        test_size=0.2,
        random_state=42,
        stratify=labels_f
    )
    print(f"      → Train: {len(X_train)} | Test: {len(X_test)}")

    # ── 3. Pipeline TF-IDF + LogReg ──
    print("\n[3/4] Entraînement du pipeline NLP...")
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 3),        # unigrams + bigrams + trigrams
            max_features=15000,        # top 15k features
            min_df=2,                  # ignorer les mots rares
            max_df=0.95,               # ignorer les mots trop fréquents
            sublinear_tf=True,         # log(TF) pour éviter le biais de fréquence
            strip_accents="unicode",
        )),
        ("clf", LogisticRegression(
            C=5.0,                     # régularisation
            max_iter=1000,
            solver="lbfgs",
            
            class_weight="balanced",   # compenser les classes déséquilibrées
            n_jobs=-1,
            random_state=42,
        ))
    ])
    
    pipeline.fit(X_train, y_train)
    print("      → Pipeline entraîné")

    # ── 4. Évaluation ──
    print("\n[4/4] Évaluation...")
    y_pred = pipeline.predict(X_test)
    
    # Cross-validation
    cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring="f1_macro", n_jobs=-1)
    print(f"\n      F1-Macro (5-fold CV): {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
    
    # Accuracy
    accuracy = (np.array(y_pred) == np.array(y_test)).mean()
    print(f"      Test Accuracy:        {accuracy:.3f}")
    
    # Rapport détaillé
    print("\n" + "─" * 55)
    print(classification_report(y_test, y_pred, zero_division=0))

    # ── Sauvegarder le modèle ──
    model_data = {
        "pipeline":      pipeline,
        "classes":       TARGET_CLASSES,
        "n_train":       len(X_train),
        "n_test":        len(X_test),
        "accuracy":      round(accuracy, 4),
        "cv_f1_macro":   round(cv_scores.mean(), 4),
        "cv_f1_std":     round(cv_scores.std(), 4),
    }
    joblib.dump(model_data, MODEL_PATH)
    print(f"\n✅ Modèle sauvegardé → {MODEL_PATH}")
    print(f"   Accuracy: {accuracy:.1%} | F1-Macro (CV): {cv_scores.mean():.3f}")
    return pipeline

# ─── Predict ─────────────────────────────────────────────────────────────────
def load_model():
    """Charger le modèle depuis le disque."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Modèle non trouvé: {MODEL_PATH}\nLancez: python3 nlp_classifier.py train")
    return joblib.load(MODEL_PATH)

def predict(text: str, top_k: int = 3) -> dict:
    """Prédire le type d'attaque pour une description CVE."""
    model_data = load_model()
    pipeline   = model_data["pipeline"]
    
    clean = preprocess(text)
    if not clean:
        return {"attack_type": "UNKNOWN", "confidence": 0.0, "top_k": []}
    
    proba  = pipeline.predict_proba([clean])[0]
    classes = pipeline.classes_
    
    # Top-k prédictions
    top_indices = np.argsort(proba)[::-1][:top_k]
    top_preds   = [
        {"type": classes[i], "confidence": round(float(proba[i]), 4)}
        for i in top_indices
    ]
    
    best_class = classes[top_indices[0]]
    best_conf  = float(proba[top_indices[0]])
    
    # Si confidence trop faible → UNKNOWN
    if best_conf < 0.30:
        best_class = "UNKNOWN"
    
    return {
        "attack_type": best_class,
        "confidence":  round(best_conf, 4),
        "top_k":       top_preds
    }

# ─── Reclassify DB ───────────────────────────────────────────────────────────
def reclassify(only_unknown: bool = True, batch_size: int = 200):
    """Re-classifier les CVE en DB avec le modèle NLP."""
    model_data = load_model()
    pipeline   = model_data["pipeline"]
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    # Charger les CVE à re-classifier
    if only_unknown:
        query = """
            SELECT id, description, attack_type FROM cve 
            WHERE description IS NOT NULL AND description != ''
              AND (attack_type = 'UNKNOWN' OR attack_type IS NULL)
        """
        print("[NLP] Re-classification des CVE UNKNOWN...")
    else:
        query = """
            SELECT id, description, attack_type FROM cve
            WHERE description IS NOT NULL AND description != ''
        """
        print("[NLP] Re-classification de TOUS les CVE...")
    
    rows = conn.execute(query).fetchall()
    print(f"[NLP] {len(rows)} CVE à traiter...")
    
    if not rows:
        print("[NLP] Aucun CVE à re-classifier.")
        conn.close()
        return
    
    # Traitement par batch
    updated  = 0
    changed  = 0
    
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        texts = [preprocess(r["description"]) for r in batch]
        
        # Prédictions batch
        probas  = pipeline.predict_proba(texts)
        classes = pipeline.classes_
        
        updates = []
        for j, (row, proba) in enumerate(zip(batch, probas)):
            best_idx   = np.argmax(proba)
            best_class = str(classes[best_idx])
            best_conf  = float(proba[best_idx])
            
            # Seuil de confiance
            if best_conf < 0.30:
                best_class = "UNKNOWN"
            
            old_type = row["attack_type"]
            if best_class != old_type:
                changed += 1
            
            updates.append((best_class, round(best_conf, 4), row["id"]))
            updated += 1
        
        # Update DB
        conn.executemany(
            "UPDATE cve SET attack_type = ? WHERE id = ?",
            [(u[0], u[2]) for u in updates]
        )
        conn.commit()
        
        done = min(i + batch_size, len(rows))
        print(f"[NLP] {done}/{len(rows)} traités... ({changed} changements)")
    
    conn.close()
    print(f"\n✅ Re-classification terminée:")
    print(f"   Total traités : {updated}")
    print(f"   Changements   : {changed}")

# ─── Integrate avec cve_enricher ─────────────────────────────────────────────
class NLPClassifier:
    """Classe singleton pour utilisation dans cve_enricher.py"""
    
    _instance = None
    _pipeline = None
    
    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        try:
            model_data   = load_model()
            self._pipeline = model_data["pipeline"]
            self._ready    = True
            print(f"[NLP] Modèle chargé — Accuracy: {model_data.get('accuracy','?')}")
        except FileNotFoundError:
            self._ready = False
            print("[NLP] Modèle non trouvé — fallback regex actif")
    
    def classify(self, description: str) -> str:
        """Classifier une description CVE."""
        if not self._ready or not description:
            return None  # None = fallback vers regex
        
        result = predict(description)
        return result["attack_type"]
    
    def classify_with_confidence(self, description: str) -> dict:
        """Classifier avec score de confiance."""
        if not self._ready or not description:
            return {"attack_type": "UNKNOWN", "confidence": 0.0, "source": "fallback"}
        
        result = predict(description)
        result["source"] = "nlp"
        return result
    
    @property
    def is_ready(self):
        return self._ready

# ─── CLI ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    
    cmd = sys.argv[1].lower()
    
    if cmd == "train":
        train()
    
    elif cmd == "predict":
        if len(sys.argv) < 3:
            print("Usage: python3 nlp_classifier.py predict '<description>'")
            sys.exit(1)
        text   = " ".join(sys.argv[2:])
        result = predict(text)
        print(f"\nDescription : {text[:100]}...")
        print(f"Prediction  : {result['attack_type']} (confidence: {result['confidence']:.1%})")
        print(f"Top-3       :")
        for p in result["top_k"]:
            bar = "█" * int(p["confidence"] * 30)
            print(f"  {p['type']:<20} {p['confidence']:.1%}  {bar}")
    
    elif cmd == "reclassify":
        only_unknown = "--all" not in sys.argv
        reclassify(only_unknown=only_unknown)
    
    elif cmd == "status":
        if os.path.exists(MODEL_PATH):
            data = joblib.load(MODEL_PATH)
            print(f"✅ Modèle présent")
            print(f"   Accuracy    : {data.get('accuracy','?')}")
            print(f"   F1-Macro CV : {data.get('cv_f1_macro','?')} ± {data.get('cv_f1_std','?')}")
            print(f"   Train set   : {data.get('n_train','?')} CVE")
        else:
            print(f"❌ Modèle absent — lancez: python3 nlp_classifier.py train")
    
    else:
        print(f"Commande inconnue: {cmd}")
        print("Commandes: train | predict '<text>' | reclassify [--all] | status")

