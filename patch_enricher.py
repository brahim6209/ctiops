"""
patch_enricher.py — Intègre le NLP classifier dans cve_enricher.py
Remplace classify_attack_type() regex par NLP quand le modèle est disponible
"""

path = "/home/br1kx/cti/ctiops/cve_enricher.py"
content = open(path).read()

# ── 1. Ajouter l'import NLP en haut du fichier ──
old_import = "import re"
new_import = """import re

# ─── NLP Classifier (remplace les regex si modèle disponible) ────────────────
try:
    from nlp_classifier import NLPClassifier as _NLPClassifier
    _nlp = _NLPClassifier.get()
except Exception as _e:
    _nlp = None
    print(f"[CVE Enricher] NLP non disponible: {_e}")"""

if "from nlp_classifier import" not in content:
    content = content.replace(old_import, new_import, 1)
    print(" Import NLP ajouté")
else:
    print("  Import NLP déjà présent")

# ── 2. Remplacer classify_attack_type pour utiliser NLP en priorité ──
old_classify = '''def classify_attack_type(description: str) -> str:
    """Classifier le type d'attaque depuis la description CVE."""
    if not description:
        return "UNKNOWN"
    desc_lower = description.lower()
    scores = {}
    for attack_type, patterns in ATTACK_PATTERNS.items():
        score = 0
        for pattern in patterns:
            if re.search(pattern, desc_lower):
                score += 1
        if score > 0:
            scores[attack_type] = score
    if not scores:
        return "UNKNOWN"
    return max(scores, key=scores.get)'''

new_classify = '''def classify_attack_type(description: str) -> str:
    """Classifier le type d'attaque depuis la description CVE.
    
    Priorité:
    1. NLP (TF-IDF + LogisticRegression) si modèle disponible
    2. Fallback regex si NLP absent ou confidence < 0.30
    """
    if not description:
        return "UNKNOWN"
    
    # ── NLP classifier (prioritaire) ──
    if _nlp is not None and _nlp.is_ready:
        result = _nlp.classify_with_confidence(description)
        if result["attack_type"] != "UNKNOWN":
            return result["attack_type"]
    
    # ── Fallback regex ──
    desc_lower = description.lower()
    scores = {}
    for attack_type, patterns in ATTACK_PATTERNS.items():
        score = 0
        for pattern in patterns:
            if re.search(pattern, desc_lower):
                score += 1
        if score > 0:
            scores[attack_type] = score
    if not scores:
        return "UNKNOWN"
    return max(scores, key=scores.get)'''

if old_classify in content:
    content = content.replace(old_classify, new_classify)
    print(" classify_attack_type patché avec NLP")
else:
    print(" Pattern classify_attack_type non trouvé — vérifiez manuellement")
    print("   Cherchez: def classify_attack_type(description: str)")

# ── Sauvegarder ──
open(path, 'w').write(content)
print(f"\n {path} mis à jour")
print("\nProchain run d'enrichissement utilisera le NLP.")

