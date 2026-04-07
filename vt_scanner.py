"""
VirusTotal Scanner automatique pour les IOC.
Scan automatique à chaque collecte d'IOC.
Rate limit gratuit : 4 req/min, 500 req/jour.
"""
import requests, urllib3, time, os
from dotenv import load_dotenv
from database import get_conn

urllib3.disable_warnings()
load_dotenv('/home/br1kx/cti/ctiops/.env')
VT_KEY = os.getenv('VIRUSTOTAL_API_KEY')

VT_BASE = "https://www.virustotal.com/api/v3"
VT_HDR  = {"x-apikey": VT_KEY}

def vt_scan_ip(ip: str) -> dict:
    """Scanner une IP sur VirusTotal."""
    try:
        r = requests.get(f"{VT_BASE}/ip_addresses/{ip}",
                        headers=VT_HDR, timeout=15)
        if r.status_code == 200:
            d    = r.json().get('data',{}).get('attributes',{})
            stats = d.get('last_analysis_stats',{})
            results = d.get('last_analysis_results',{})
            malicious_engines = [k for k,v in results.items() 
                                  if v.get('category')=='malicious']
            suspicious_engines = [k for k,v in results.items()
                                   if v.get('category')=='suspicious']
            return {
                "vt_malicious"  : stats.get('malicious', 0),
                "vt_suspicious" : stats.get('suspicious', 0),
                "vt_harmless"   : stats.get('harmless', 0),
                "vt_verdict"    : "MALICIOUS"   if stats.get('malicious',0) > 3
                                  else "SUSPICIOUS" if stats.get('malicious',0) > 0 or stats.get('suspicious',0) > 0
                                  else "CLEAN",
                "vt_engines"    : malicious_engines[:8],
                "vt_country"    : d.get('country',''),
                "vt_owner"      : d.get('as_owner',''),
                "vt_asn"        : d.get('asn',''),
                "vt_tags"       : d.get('tags',[]),
                "vt_score"      : stats.get('malicious',0),
            }
        elif r.status_code == 429:
            print("[VT] Rate limit — attente 60s")
            time.sleep(60)
    except Exception as e:
        print(f"[VT] Error {ip}: {e}")
    return {}

def vt_scan_url(url: str) -> dict:
    """Scanner une URL sur VirusTotal."""
    import base64
    try:
        # Encoder l'URL en base64 URL-safe sans padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        r = requests.get(f"{VT_BASE}/urls/{url_id}",
                        headers=VT_HDR, timeout=15)
        if r.status_code == 200:
            d     = r.json().get('data',{}).get('attributes',{})
            stats = d.get('last_analysis_stats',{})
            return {
                "vt_malicious" : stats.get('malicious', 0),
                "vt_suspicious": stats.get('suspicious', 0),
                "vt_verdict"   : "MALICIOUS"   if stats.get('malicious',0) > 3
                                 else "SUSPICIOUS" if stats.get('malicious',0) > 0
                                 else "CLEAN",
                "vt_score"     : stats.get('malicious', 0),
            }
    except Exception as e:
        print(f"[VT] Error URL {url}: {e}")
    return {}

def vt_scan_hash(hash_val: str) -> dict:
    """Scanner un hash (MD5/SHA256) sur VirusTotal."""
    try:
        r = requests.get(f"{VT_BASE}/files/{hash_val}",
                        headers=VT_HDR, timeout=15)
        if r.status_code == 200:
            d     = r.json().get('data',{}).get('attributes',{})
            stats = d.get('last_analysis_stats',{})
            return {
                "vt_malicious"  : stats.get('malicious', 0),
                "vt_suspicious" : stats.get('suspicious', 0),
                "vt_verdict"    : "MALICIOUS"   if stats.get('malicious',0) > 3
                                  else "SUSPICIOUS" if stats.get('malicious',0) > 0
                                  else "CLEAN",
                "vt_score"      : stats.get('malicious', 0),
                "vt_name"       : d.get('meaningful_name',''),
                "vt_family"     : d.get('popular_threat_classification',{}).get('suggested_threat_label',''),
            }
    except Exception as e:
        print(f"[VT] Error hash {hash_val}: {e}")
    return {}

def vt_scan_ioc(ioc_type: str, value: str) -> dict:
    """Router vers la bonne fonction VT selon le type."""
    if ioc_type in ('ip', 'ip-dst', 'ip-src', 'IPv4'):
        return vt_scan_ip(value)
    elif ioc_type in ('url', 'URL'):
        return vt_scan_url(value)
    elif ioc_type in ('md5', 'sha256', 'sha1', 'FileHash-MD5', 'FileHash-SHA256'):
        return vt_scan_hash(value)
    return {}

def batch_scan_iocs(limit: int = 20, force: bool = False):
    """
    Scanner automatiquement les IOC non encore scannés par VT.
    Respecte le rate limit : 4 req/min (1 req/15s).
    """
    with get_conn() as c:
        if force:
            # Re-scanner tous les IOC
            iocs = c.execute(
                "SELECT id, type, value FROM ioc LIMIT ?", (limit,)
            ).fetchall()
        else:
            # Scanner uniquement les IOC pas encore scannés (vt_score = 0 et verdict PENDING)
            iocs = c.execute("""
                SELECT id, type, value FROM ioc
                WHERE vt_verdict = 'PENDING' OR vt_verdict IS NULL
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()

    if not iocs:
        print("[VT] Tous les IOC sont déjà scannés")
        return 0

    print(f"[VT] Scan de {len(iocs)} IOC...")
    scanned = 0

    for ioc in iocs:
        ioc_id, ioc_type, value = ioc['id'], ioc['type'], ioc['value']
        print(f"[VT] Scanning {ioc_type}: {value}...")

        result = vt_scan_ioc(ioc_type, value)

        if result:
            with get_conn() as c:
                c.execute("""
                    UPDATE ioc SET
                        vt_malicious = ?,
                        vt_verdict   = ?,
                        vt_score     = ?
                    WHERE id = ?
                """, (
                    result.get('vt_malicious', 0),
                    result.get('vt_verdict', 'UNKNOWN'),
                    result.get('vt_score', 0),
                    ioc_id
                ))
            print(f"  → {result.get('vt_verdict')} ({result.get('vt_malicious',0)} engines)")
            scanned += 1

        # Rate limit : 4 req/min = 1 req/15s
        time.sleep(16)

    print(f"[VT] Batch terminé: {scanned}/{len(iocs)} scannés")
    return scanned

def register_vt_routes(app):
    from flask import request, jsonify

    @app.route("/api/v1/vt/scan-ioc")
    def api_vt_scan():
        """Scan VT d'un IOC spécifique."""
        value    = request.args.get('value','')
        ioc_type = request.args.get('type','ip')
        if not value:
            return jsonify({"error": "value required"}), 400

        result = vt_scan_ioc(ioc_type, value)
        if not result:
            return jsonify({"error": "VT lookup failed"}), 500

        # Sauvegarder dans DB si IOC existe
        with get_conn() as c:
            c.execute("""
                UPDATE ioc SET
                    vt_malicious = ?,
                    vt_verdict   = ?,
                    vt_score     = ?
                WHERE value = ?
            """, (result.get('vt_malicious',0),
                  result.get('vt_verdict','UNKNOWN'),
                  result.get('vt_score',0), value))

        return jsonify({"ioc": value, "type": ioc_type, **result})

    @app.route("/api/v1/vt/batch-scan", methods=["POST"])
    def api_vt_batch():
        """Lancer un scan VT batch sur les IOC non scannés."""
        limit = int(request.json.get('limit', 10) if request.json else 10)
        force = bool(request.json.get('force', False) if request.json else False)

        # Lancer en background
        import threading
        t = threading.Thread(target=batch_scan_iocs, args=(limit, force))
        t.daemon = True
        t.start()

        return jsonify({
            "status" : "started",
            "message": f"Scan VT lancé pour {limit} IOC en arrière-plan",
            "rate_limit": "4 req/min (plan gratuit)"
        })

    @app.route("/api/v1/vt/stats")
    def api_vt_stats():
        """Statistiques des scans VT."""
        with get_conn() as c:
            stats = c.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN vt_verdict='MALICIOUS'   THEN 1 ELSE 0 END) as malicious,
                    SUM(CASE WHEN vt_verdict='SUSPICIOUS'  THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN vt_verdict='CLEAN'       THEN 1 ELSE 0 END) as clean,
                    SUM(CASE WHEN vt_verdict='PENDING'     THEN 1 ELSE 0 END) as pending,
                    MAX(vt_malicious) as max_engines
                FROM ioc
            """).fetchone()

            top_malicious = c.execute("""
                SELECT value, type, source, vt_malicious, vt_verdict
                FROM ioc
                WHERE vt_verdict='MALICIOUS'
                ORDER BY vt_malicious DESC LIMIT 10
            """).fetchall()

        return jsonify({
            "stats"        : dict(stats),
            "top_malicious": [dict(r) for r in top_malicious]
        })
