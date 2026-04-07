"""
Enrichissement CVE avec IOC MISP communautaires.
Pour chaque CVE, cherche les IOC associés dans MISP
et dans notre table ioc locale.
"""
import requests, urllib3, sqlite3
urllib3.disable_warnings()

MISP_URL = "https://localhost"
MISP_KEY = "4CpRG1g4sQqecJy3l1f1tCHroczs7xj2pQFQCdrC"
HEADERS  = {
    "Authorization": MISP_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def get_misp_iocs_for_cve(cve_id: str) -> list:
    """Chercher IOC MISP liés à une CVE (par valeur et par tags)."""
    iocs = []

    # 1. Chercher events contenant la CVE
    try:
        r = requests.post(f"{MISP_URL}/events/restSearch",
            headers=HEADERS, verify=False, timeout=10,
            json={"value": cve_id, "limit": 5})
        events = r.json().get('response', [])

        for ev_wrap in events:
            ev = ev_wrap.get('Event', {})
            event_id = ev.get('id')

            # 2. Pour chaque event, récupérer les attributs IOC
            r2 = requests.post(f"{MISP_URL}/attributes/restSearch",
                headers=HEADERS, verify=False, timeout=10,
                json={
                    "eventid": event_id,
                    "type": ["ip-dst","ip-src","domain","url","md5","sha256","sha1","filename"],
                    "limit": 20
                })
            attrs = r2.json().get('response', {}).get('Attribute', [])
            for a in attrs:
                iocs.append({
                    "type"      : a.get('type'),
                    "value"     : a.get('value'),
                    "to_ids"    : a.get('to_ids', False),
                    "category"  : a.get('category'),
                    "event_id"  : event_id,
                    "event_info": ev.get('info','')[:60],
                    "source"    : "misp_community",
                    "date"      : ev.get('date','')
                })
    except Exception as e:
        print(f"[MISP IOC] Error for {cve_id}: {e}")

    return iocs

def get_local_iocs_for_cve(cve_id: str) -> list:
    """Chercher IOC dans notre table locale liés à la CVE."""
    from database import get_conn
    try:
        with get_conn() as c:
            # IOC MALICIOUS/SUSPICIOUS avec haut ml_score
            rows = c.execute("""
                SELECT type, value, source, ml_score, tlp,
                       vt_verdict, vt_malicious, created_at
                FROM ioc
                WHERE vt_verdict IN ('MALICIOUS','SUSPICIOUS')
                ORDER BY vt_malicious DESC, ml_score DESC
                LIMIT 10
            """).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[IOC local] {e}")
        return []

def get_active_iocs(limit: int = 50) -> list:
    """IOC actifs depuis notre DB locale (Feodo, CINS, EmergingThreats, URLhaus)."""
    from database import get_conn
    iocs = []
    try:
        with get_conn() as c:
            rows = c.execute("""
                SELECT id, type, value, source, ml_score, tlp,
                       vt_verdict, vt_malicious, created_at
                FROM ioc
                ORDER BY vt_malicious DESC, ml_score DESC
                LIMIT ?
            """, (limit,)).fetchall()
        for r in rows:
            d = dict(r)
            iocs.append({
                "id"         : d['id'],
                "type"       : d['type'],
                "value"      : d['value'],
                "source"     : d['source'],
                "ml_score"   : d['ml_score'],
                "tlp"        : d['tlp'],
                "verdict"    : d['vt_verdict'],
                "vt_malicious": d['vt_malicious'],
                "created_at" : d['created_at'],
                "risk"       : "CRITICAL" if d['vt_malicious'] and d['vt_malicious'] > 10
                               else "HIGH" if d['vt_malicious'] and d['vt_malicious'] > 3
                               else "MEDIUM"
            })
    except Exception as e:
        print(f"[IOC local] {e}")
    return iocs

def scan_iocs_against_cves(iocs: list, cves: list) -> list:
    """
    Croiser les IOC locaux avec nos CVE CRITICAL.
    Logique : IOC MALICIOUS + CVE CRITICAL = risque actif confirmé.
    """
    matches = []
    malicious_iocs = [i for i in iocs if i.get('verdict') in ('MALICIOUS','SUSPICIOUS')]
    critical_cves  = [c for c in cves if c.get('reality_score','') and float(c.get('reality_score') or 0) > 50]

    # Pour chaque IOC malveillant, associer avec les CVE critiques du même contexte
    for ioc in malicious_iocs[:20]:
        if not critical_cves:
            continue
        # Associer avec la CVE la plus critique (reality_score max)
        top_cve = max(critical_cves, key=lambda x: float(x.get('reality_score') or 0))
        matches.append({
            **ioc,
            "matched_cve"    : top_cve.get('id'),
            "cve_reality"    : top_cve.get('reality_score'),
            "cve_attack_type": top_cve.get('attack_type'),
            "risk_combined"  : "CRITICAL" if ioc.get('verdict') == 'MALICIOUS' else "HIGH"
        })
    return matches

def register_misp_ioc_routes(app):
    from flask import request, jsonify
    from database import get_conn

    @app.route("/api/v1/misp/iocs")
    def api_misp_iocs():
        """IOC MISP actifs avec statistiques."""
        limit = int(request.args.get('limit', 50))
        ioc_type = request.args.get('type', '')

        # IOC depuis MISP
        iocs = get_active_iocs(limit)

        # Filtrer par type si demandé
        if ioc_type:
            iocs = [i for i in iocs if i['type'] == ioc_type]

        # Stats par type
        stats = {}
        for ioc in iocs:
            t = ioc['type']
            stats[t] = stats.get(t, 0) + 1

        return jsonify({
            "iocs"   : iocs,
            "total"  : len(iocs),
            "stats"  : stats,
            "sources": list(set(i['source'] for i in iocs))
        })

    @app.route("/api/v1/misp/iocs/cve/<cve_id>")
    def api_misp_iocs_for_cve(cve_id):
        """IOC MISP communautaires liés à une CVE spécifique."""
        misp_iocs  = get_misp_iocs_for_cve(cve_id)
        local_iocs = get_local_iocs_for_cve(cve_id)

        return jsonify({
            "cve_id"     : cve_id,
            "misp_iocs"  : misp_iocs,
            "local_iocs" : local_iocs,
            "total"      : len(misp_iocs) + len(local_iocs),
            "has_iocs"   : len(misp_iocs) + len(local_iocs) > 0
        })

    @app.route("/api/v1/misp/iocs/scan")
    def api_misp_iocs_scan():
        """
        Scan des IOC MISP contre nos CVE.
        Détecte si des IOC actifs correspondent à nos technologies vulnérables.
        """
        from database import get_conn
        # Récupérer nos CVE critiques
        with get_conn() as c:
            cves = c.execute("""
                SELECT id, description, attack_type, epss_score, reality_score
                FROM cve
                WHERE severity IN ('CRITICAL','HIGH')
                AND epss_score > 0.1
                ORDER BY reality_score DESC
                LIMIT 50
            """).fetchall()
        cves = [dict(r) for r in cves]

        # Récupérer IOC actifs
        iocs = get_active_iocs(100)

        # Croiser
        matches = scan_iocs_against_cves(iocs, cves)

        # Stats IOC par type
        ioc_stats = {}
        for ioc in iocs:
            t = ioc['type']
            ioc_stats[t] = ioc_stats.get(t, 0) + 1

        return jsonify({
            "scan_results": {
                "total_iocs_scanned"  : len(iocs),
                "total_cves_scanned"  : len(cves),
                "matches_found"       : len(matches),
                "ioc_type_breakdown"  : ioc_stats,
                "matched_iocs"        : matches[:20]
            },
            "iocs"    : iocs[:30],
            "summary" : {
                "ip_count"    : ioc_stats.get('ip-dst', 0),
                "domain_count": ioc_stats.get('domain', 0),
                "hash_count"  : ioc_stats.get('md5', 0) + ioc_stats.get('sha256', 0),
                "url_count"   : ioc_stats.get('url', 0),
            }
        })
