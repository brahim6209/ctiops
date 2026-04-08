"""
threat_intel.py — Threat Intelligence + Breach Check
Sources: URLhaus, Feodo, ThreatFox + LeakCheck + HIBP k-anonymity
"""
import requests, os, json, hashlib
from dotenv import load_dotenv
from database import get_conn, insert_ioc

load_dotenv('/home/br1kx/cti/ctiops/.env')

LEAKCHECK_KEY = os.getenv("LEAKCHECK_API_KEY", "")

# ── LEAKCHECK ─────────────────────────────────────────────────────
def check_email_leakcheck(email: str) -> dict:
    if not LEAKCHECK_KEY:
        return {"error": "LEAKCHECK_API_KEY manquant"}
    try:
        r = requests.get(
            "https://leakcheck.io/api/v2/query",
            headers={"X-API-Key": LEAKCHECK_KEY},
            params={"query": email, "type": "email"},
            timeout=15
        )
        data = r.json()
        if not data.get("success"):
            error_msg = data.get("error", "Unknown")
            if "plan" in error_msg.lower():
                # Plan gratuit - utiliser lookup par domaine uniquement
                return {
                    "email":   email,
                    "breached": None,
                    "status":  "PLAN_REQUIRED",
                    "note":    "LeakCheck requiert un plan payant pour email lookup. Utilisez /breach/password ou /breach/username",
                    "alternatives": [
                        "POST /api/v1/breach/password — vérifie le mot de passe (gratuit)",
                        "POST /api/v1/breach/username — vérifie le username (gratuit)",
                    ]
                }
            return {"email": email, "error": error_msg}
        found   = data.get("found", 0)
        sources = data.get("sources", [])
        return {
            "email":    email,
            "breached": found > 0,
            "count":    found,
            "status":   "COMPROMISED" if found > 0 else "CLEAN",
            "risk":     "CRITICAL" if found > 3 else "HIGH" if found > 0 else "LOW",
            "breaches": [{
                "name":              s.get("name", ""),
                "date":              s.get("date", ""),
                "data_classes":      s.get("fields", []),
                "password_included": "password" in [f.lower() for f in s.get("fields", [])],
            } for s in sources[:10]],
            "has_password_leak": any(
                "password" in [f.lower() for f in s.get("fields", [])]
                for s in sources
            ),
            "source": "LeakCheck"
        }
    except Exception as e:
        return {"email": email, "error": str(e)}

def check_domain_leakcheck(domain: str) -> dict:
    if not LEAKCHECK_KEY:
        return {"error": "LEAKCHECK_API_KEY manquant"}
    try:
        r = requests.get(
            "https://leakcheck.io/api/v2/query",
            headers={"X-API-Key": LEAKCHECK_KEY},
            params={"query": domain, "type": "domain"},
            timeout=15
        )
        data    = r.json()
        found   = data.get("found", 0)
        sources = data.get("sources", [])
        return {
            "domain":   domain,
            "breached": found > 0,
            "count":    found,
            "status":   "COMPROMISED" if found > 0 else "CLEAN",
            "risk":     "CRITICAL" if found > 10 else "HIGH" if found > 0 else "LOW",
            "breaches": [{"name": s.get("name",""), "date": s.get("date",""), "fields": s.get("fields",[])} for s in sources[:10]],
            "source": "LeakCheck"
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}

def check_username_leakcheck(username: str) -> dict:
    if not LEAKCHECK_KEY:
        return {"error": "LEAKCHECK_API_KEY manquant"}
    try:
        r = requests.get(
            "https://leakcheck.io/api/v2/query",
            headers={"X-API-Key": LEAKCHECK_KEY},
            params={"query": username, "type": "username"},
            timeout=15
        )
        data    = r.json()
        found   = data.get("found", 0)
        sources = data.get("sources", [])
        return {
            "username": username,
            "breached": found > 0,
            "count":    found,
            "status":   "COMPROMISED" if found > 0 else "CLEAN",
            "breaches": [{"name": s.get("name",""), "date": s.get("date",""), "fields": s.get("fields",[])} for s in sources[:10]],
            "source": "LeakCheck"
        }
    except Exception as e:
        return {"username": username, "error": str(e)}

# ── HIBP PASSWORD (k-anonymity — gratuit sans clé) ────────────────
def check_password_breach(password: str) -> dict:
    sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=15
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                if ":" in line:
                    h, count = line.split(":")
                    if h == suffix:
                        return {
                            "pwned": True,
                            "count": int(count),
                            "risk":  "CRITICAL" if int(count) > 1000 else "HIGH",
                            "note":  f"Ce mot de passe a fuité {count} fois",
                        }
            return {"pwned": False, "count": 0, "risk": "LOW",
                    "note": "Mot de passe non trouvé dans les bases de fuite"}
        return {"pwned": None, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"pwned": None, "error": str(e)}

# ── THREAT FEEDS ──────────────────────────────────────────────────
def fetch_urlhaus(limit: int = 100) -> int:
    """Collecte IOC depuis sources ouvertes — abuse.ch + OpenPhish + CINSscore."""
    count = 0

    # Source 1 — abuse.ch ThreatFox (REST API publique)
    try:
        import requests
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=20
        )
        if r.status_code == 200:
            for entry in r.json().get("data", [])[:limit]:
                ioc_val = entry.get("ioc_value", entry.get("ioc",""))
                if ioc_val:
                    insert_ioc({
                        "value":  ioc_val[:500],
                        "type":   entry.get("ioc_type","unknown"),
                        "source": "ThreatFox-daily",
                        "tlp":    "TLP:WHITE",
                    })
                    count += 1
        print(f"[ThreatFox-daily] {count} IOC")
    except Exception as e:
        print(f"[ThreatFox-daily] Erreur: {e}")

    # Source 2 — CINS Score (IPs malveillantes actives)
    try:
        r = requests.get(
            "http://cinsscore.com/list/ci-badguys.txt",
            timeout=20
        )
        if r.status_code == 200:
            ips = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith('#')]
            for ip in ips[:50]:
                insert_ioc({
                    "value":  ip,
                    "type":   "ip",
                    "source": "CINS-Score",
                    "tlp":    "TLP:WHITE",
                })
                count += 1
        print(f"[CINS] {len(ips[:50])} IPs")
    except Exception as e:
        print(f"[CINS] Erreur: {e}")

    # Source 3 — Emerging Threats (IPs compromises)
    try:
        r = requests.get(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            timeout=20
        )
        if r.status_code == 200:
            ips = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith('#')]
            added = 0
            for ip in ips[:100]:
                insert_ioc({
                    "value":  ip,
                    "type":   "ip",
                    "source": "EmergingThreats",
                    "tlp":    "TLP:WHITE",
                })
                added += 1
                count += 1
            print(f"[EmergingThreats] {added} IPs")
    except Exception as e:
        print(f"[EmergingThreats] Erreur: {e}")

    return count


def fetch_feodo() -> int:
    print("[Feodo] Collecte IPs botnet C2...")
    try:
        r = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            timeout=30
        )
        data = r.json()
        # Feodo retourne soit {"blocklist":[...]} soit une liste directe
        if isinstance(data, list):
            blocklist = data
        else:
            blocklist = data.get("blocklist", data if isinstance(data, list) else [])
        count = 0
        for entry in blocklist:
            if not isinstance(entry, dict): continue
            if entry.get("ip_address"):
                try:
                    insert_ioc({
                        "value":  entry["ip_address"],
                        "type":   "ip",
                        "source": "Feodo-C2",
                        "tlp":    "TLP:RED",
                    })
                    count += 1
                except:
                    pass
        print(f"[Feodo] {count} IPs C2")
        return count
    except Exception as e:
        print(f"[Feodo] Erreur: {e}")
        return 0

def fetch_threatfox(days: int = 7) -> int:
    print("[ThreatFox] Collecte IOC...")
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": days}, timeout=30
        )
        count = 0
        for entry in r.json().get("data", []):
            try:
                insert_ioc({
                    "value":  entry.get("ioc",""),
                    "type":   entry.get("ioc_type","unknown"),
                    "source": "ThreatFox",
                    "tlp":    "TLP:AMBER",
                })
                count += 1
            except:
                pass
        print(f"[ThreatFox] {count} IOC")
        return count
    except Exception as e:
        print(f"[ThreatFox] Erreur: {e}")
        return 0

def monitor_zerodays_for_components(components: list) -> list:
    alerts = []
    with get_conn() as c:
        for component in components:
            name = component.get("name","").lower() if isinstance(component, dict) else component.lower()
            rows = c.execute("""
                SELECT id, cvss_score, severity, description,
                       has_exploit, actively_exploited, epss_score
                FROM cve
                WHERE LOWER(description) LIKE ? OR LOWER(keywords) LIKE ?
                ORDER BY cvss_score DESC LIMIT 5
            """, [f"%{name}%", f"%{name}%"]).fetchall()
            for row in rows:
                d = dict(row)
                if ((d.get("cvss_score") or 0) >= 7.0 and
                    (d.get("has_exploit") or d.get("actively_exploited") or
                     (d.get("epss_score") or 0) > 0.3)):
                    alerts.append({
                        "component":          name,
                        "cve_id":             d["id"],
                        "cvss":               d.get("cvss_score"),
                        "severity":           d.get("severity"),
                        "has_exploit":        bool(d.get("has_exploit")),
                        "actively_exploited": bool(d.get("actively_exploited")),
                        "epss_score":         d.get("epss_score"),
                        "description":        (d.get("description") or "")[:150],
                        "alert_level":        "CRITICAL" if d.get("actively_exploited") else "HIGH",
                    })
    return alerts

def run_threat_intel_collector(days: int = 7) -> dict:
    results = {
        "urlhaus":   fetch_urlhaus(100),
        "feodo":     fetch_feodo(),
        "threatfox": fetch_threatfox(days),
    }
    results["total"] = sum(results.values())
    return results
# ── VIRUSTOTAL VERIFICATION ───────────────────────────────────────
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

def verify_ioc_vt(ioc_value: str, ioc_type: str) -> dict:
    """Vérifier un IOC via VirusTotal."""
    if not VT_KEY:
        return {"vt_score": 0, "vt_verdict": "NO_KEY", "vt_checked": False}
    try:
        headers = {"x-apikey": VT_KEY}

        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif ioc_type in ["hash", "md5", "sha256", "sha1"]:
            url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
        else:
            return {"vt_score": 0, "vt_verdict": "UNKNOWN_TYPE", "vt_checked": False}

        r = requests.get(url, headers=headers, timeout=15)

        if r.status_code == 200:
            data  = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) or 1
            score      = round((malicious + suspicious) / total * 100)
            reputation = attrs.get("reputation", 0)

            if malicious >= 5:
                verdict = "MALICIOUS"
            elif malicious > 0 or suspicious > 2:
                verdict = "SUSPICIOUS"
            elif malicious == 0 and suspicious == 0:
                verdict = "CLEAN"
            else:
                verdict = "UNKNOWN"

            return {
                "vt_checked":    True,
                "vt_malicious":  malicious,
                "vt_suspicious": suspicious,
                "vt_score":      score,
                "vt_verdict":    verdict,
                "vt_reputation": reputation,
                "vt_engines":    total,
            }
        elif r.status_code == 404:
            return {"vt_checked": True, "vt_verdict": "NOT_FOUND", "vt_score": 0}
        elif r.status_code == 429:
            return {"vt_checked": False, "vt_verdict": "RATE_LIMITED", "vt_score": 0}
        else:
            return {"vt_checked": False, "vt_verdict": f"HTTP_{r.status_code}", "vt_score": 0}

    except Exception as e:
        return {"vt_checked": False, "vt_verdict": "ERROR", "vt_score": 0, "vt_error": str(e)}


def verify_all_pending_iocs(limit: int = 50) -> dict:
    """Vérifier les IOC non encore vérifiés via VT."""
    print(f"[VT] Vérification de {limit} IOC pending...")

    # Ajouter colonnes VT si manquantes
    with get_conn() as c:
        existing = [col[1] for col in c.execute("PRAGMA table_info(ioc)").fetchall()]
        for col, typ in [
            ("vt_score",     "INTEGER DEFAULT 0"),
            ("vt_verdict",   "TEXT DEFAULT 'PENDING'"),
            ("vt_malicious", "INTEGER DEFAULT 0"),
        ]:
            if col not in existing:
                c.execute(f"ALTER TABLE ioc ADD COLUMN {col} {typ}")
                print(f"  Colonne ajoutée: {col}")

        pending = c.execute("""
            SELECT id, value, type FROM ioc
            WHERE vt_verdict IS NULL
               OR vt_verdict = 'PENDING'
            LIMIT ?
        """, (limit,)).fetchall()

    print(f"[VT] {len(pending)} IOC à vérifier")
    verified = 0; malicious = 0; suspicious = 0

    for ioc in pending:
        result = verify_ioc_vt(ioc["value"], ioc["type"])
        with get_conn() as c:
            c.execute("""
                UPDATE ioc SET
                    vt_score     = ?,
                    vt_verdict   = ?,
                    vt_malicious = ?
                WHERE id = ?
            """, (
                result.get("vt_score", 0),
                result.get("vt_verdict", "UNKNOWN"),
                result.get("vt_malicious", 0),
                ioc["id"]
            ))
        if result.get("vt_checked"):
            verified += 1
        if result.get("vt_verdict") == "MALICIOUS":
            malicious += 1
        elif result.get("vt_verdict") == "SUSPICIOUS":
            suspicious += 1
        time.sleep(0.25)  # 4 req/s max VT gratuit

    print(f"[VT] Done: {verified} vérifiés | {malicious} MALICIOUS | {suspicious} SUSPICIOUS")
    return {"verified": verified, "malicious": malicious, "suspicious": suspicious}


