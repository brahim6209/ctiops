"""
secret_checker.py — Vérification gratuite des secrets par type
- telegram-bot-api-token → API Telegram getMe
- generic-api-key (password-like) → HIBP k-anonymity
- username-like → LeakCheck username (gratuit)
"""
import hashlib, requests, re

def classify_secret(rule_id: str, secret_hint: str, context: str = "") -> str:
    """Classifier le type de secret pour choisir la méthode de vérification."""
    if "telegram" in rule_id.lower():
        return "telegram_token"
    if "password" in rule_id.lower() or "passwd" in rule_id.lower():
        return "password"
    if "username" in rule_id.lower() or "user" in rule_id.lower():
        return "username"
    if "jwt" in rule_id.lower() or "jwt" in context.lower():
        return "jwt_secret"
    # generic-api-key — analyser le contexte
    ctx = context.lower()
    if any(k in ctx for k in ["password=", "passwd=", "pwd=", "secret="]):
        return "password"
    if any(k in ctx for k in ["username=", "user=", "login="]):
        return "username"
    if any(k in ctx for k in ["jwt", "token", "bearer"]):
        return "jwt_secret"
    return "generic_secret"

def check_telegram_token(token_hint: str) -> dict:
    """Vérifier si un token Telegram est encore actif."""
    # On ne peut pas vérifier avec juste le hint masqué
    # Mais on peut indiquer le statut
    return {
        "method": "telegram_api",
        "checked": False,
        "status": "HINT_ONLY",
        "note": "Token masqué — vérification manuelle requise via api.telegram.org/bot{TOKEN}/getMe",
        "risk": "CRITICAL"
    }

def check_password_hibp(password: str) -> dict:
    """Vérifier un password via HIBP k-anonymity (gratuit, anonyme)."""
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "CTI-Platform-SecurityCheck"},
            timeout=5
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return {
                        "method": "HIBP",
                        "checked": True,
                        "pwned": True,
                        "count": int(count),
                        "risk": "CRITICAL" if int(count) > 1000 else "HIGH",
                        "note": f"Found {count} times in known breaches"
                    }
            return {"method": "HIBP", "checked": True, "pwned": False, "risk": "LOW", "note": "Not found in breaches"}
    except Exception as e:
        return {"method": "HIBP", "checked": False, "error": str(e)}

def check_username_leakcheck(username: str) -> dict:
    """Vérifier un username via LeakCheck (gratuit pour usernames)."""
    try:
        r = requests.get(
            f"https://leakcheck.io/api/public?check={username}",
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            found = data.get("found", 0)
            return {
                "method": "LeakCheck",
                "checked": True,
                "found": found > 0,
                "count": found,
                "risk": "CRITICAL" if found > 10 else "HIGH" if found > 0 else "LOW",
                "note": f"Found in {found} breaches" if found else "Not found"
            }
    except Exception as e:
        return {"method": "LeakCheck", "checked": False, "error": str(e)}

def check_jwt_secret(secret: str) -> dict:
    """Analyser un JWT secret (statique — pas de service externe)."""
    import base64, math
    # Calculer l'entropie
    if not secret:
        return {"method": "static", "checked": True, "risk": "UNKNOWN"}
    
    freq = {}
    for c in secret:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((f/len(secret)) * math.log2(f/len(secret)) for f in freq.values())
    
    # Vérifier si c'est du base64
    is_b64 = bool(re.match(r'^[A-Za-z0-9+/=]+$', secret))
    length = len(secret)
    
    risk = "LOW"
    if length < 32: risk = "CRITICAL"  # Trop court
    elif entropy < 3.5: risk = "HIGH"   # Entropie trop basse
    else: risk = "LOW"                   # OK

    return {
        "method": "static_analysis",
        "checked": True,
        "entropy": round(entropy, 2),
        "length": length,
        "is_base64": is_b64,
        "risk": risk,
        "note": f"Entropy: {entropy:.2f}, Length: {length} chars"
    }

def check_secret(rule_id: str, secret_hint: str, context: str = "") -> dict:
    """Point d'entrée principal — choisit la méthode selon le type."""
    secret_type = classify_secret(rule_id, secret_hint, context)
    
    # Extraire les vraies valeurs connues du contexte pour les passwords/usernames
    known_passwords = ["root", "admin", "password", "123456"]
    known_usernames = ["root", "admin"]
    
    result = {"secret_type": secret_type, "rule_id": rule_id}
    
    if secret_type == "telegram_token":
        result.update(check_telegram_token(secret_hint))
    elif secret_type == "password":
        # Tester les passwords connus extraits du contexte
        for pwd in known_passwords:
            if pwd in context.lower():
                result.update(check_password_hibp(pwd))
                result["matched_value"] = pwd
                break
        else:
            result.update({"method": "HIBP", "checked": False, "note": "Password value masked — cannot check"})
    elif secret_type == "username":
        for usr in known_usernames:
            if usr in context.lower():
                result.update(check_username_leakcheck(usr))
                result["matched_value"] = usr
                break
        else:
            result.update({"method": "LeakCheck", "checked": False, "note": "Username value masked"})
    elif secret_type == "jwt_secret":
        result.update(check_jwt_secret(secret_hint.replace("*", "")))
    else:
        result.update({"method": "none", "checked": False, "risk": "UNKNOWN", "note": "Generic secret — manual review required"})
    
    return result

if __name__ == "__main__":
    # Test
    print("=== Test secret checker ===")
    print("\n1. Telegram token:")
    print(check_secret("telegram-bot-api-token", "6879940239***", "telegram.bot.username=6879940239:AAE..."))
    print("\n2. DB Password (root):")
    print(check_secret("generic-api-key", "root***", "spring.datasource.password=root"))
    print("\n3. DB Username (root):")
    print(check_secret("generic-api-key", "root***", "spring.datasource.username=root"))
    print("\n4. JWT Secret:")
    print(check_secret("generic-api-key", "WmM3OTk5***", "jwt.secret=WmM3OTk5MjQx..."))
