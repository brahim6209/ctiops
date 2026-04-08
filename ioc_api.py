"""
IOC API — Module indépendant.
Collecte, enrichissement VT/OTX/Shodan, stats.
Aucune liaison avec CVE.
"""
import requests, urllib3, time, os
from dotenv import load_dotenv
from database import get_conn

urllib3.disable_warnings()
load_dotenv('/home/br1kx/cti/ctiops/.env')
VT_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def register_ioc_routes(app):
    from flask import request, jsonify

    # ── Stats globales ────────────────────────────────────────
    @app.route("/api/v1/ioc/stats")
    def api_ioc_stats():
        with get_conn() as c:
            stats = c.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN vt_verdict='MALICIOUS'  THEN 1 ELSE 0 END) as malicious,
                    SUM(CASE WHEN vt_verdict='SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN vt_verdict='CLEAN'      THEN 1 ELSE 0 END) as clean,
                    SUM(CASE WHEN vt_verdict='PENDING' OR vt_verdict IS NULL THEN 1 ELSE 0 END) as pending,
                    MAX(vt_malicious) as max_engines
                FROM ioc
            """).fetchone()

            by_source = c.execute("""
                SELECT source,
                       COUNT(*) as total,
                       SUM(CASE WHEN vt_verdict='MALICIOUS' THEN 1 ELSE 0 END) as malicious,
                       SUM(CASE WHEN vt_verdict='PENDING' OR vt_verdict IS NULL THEN 1 ELSE 0 END) as pending
                FROM ioc
                GROUP BY source
                ORDER BY total DESC
            """).fetchall()

            top_malicious = c.execute("""
                SELECT type, value, source, vt_malicious, vt_verdict
                FROM ioc
                WHERE vt_verdict='MALICIOUS'
                ORDER BY vt_malicious DESC
                LIMIT 10
            """).fetchall()

        return jsonify({
            "stats"        : dict(stats),
            "by_source"    : [dict(r) for r in by_source],
            "top_malicious": [dict(r) for r in top_malicious]
        })

    # ── Liste IOC enrichie ────────────────────────────────────
    @app.route("/api/v1/ioc/list")
    def api_ioc_list():
        limit   = int(request.args.get('limit', 100))
        verdict = request.args.get('verdict', '')
        source  = request.args.get('source', '')
        ioc_type= request.args.get('type', '')
        enrich  = request.args.get('enrich', 'false') == 'true'

        query = "SELECT * FROM ioc WHERE 1=1"
        params = []
        if verdict:
            query += " AND vt_verdict=?"; params.append(verdict)
        if source:
            query += " AND source=?";     params.append(source)
        if ioc_type:
            query += " AND type=?";       params.append(ioc_type)
        query += " ORDER BY vt_malicious DESC, id DESC LIMIT ?"
        params.append(limit)

        with get_conn() as c:
            rows = c.execute(query, params).fetchall()

        iocs = []
        for row in rows:
            d = dict(row)

            # Enrichissement OTX si demandé
            if enrich and d.get('type') == 'ip' and d.get('vt_verdict') in ('MALICIOUS','SUSPICIOUS'):
                otx = _otx_enrich(d['value'])
                d.update(otx)

                # Shodan
                shodan = _shodan_enrich(d['value'])
                d.update(shodan)

            d['risk'] = _compute_risk(d)
            iocs.append(d)

        return jsonify({
            "iocs"   : iocs,
            "total"  : len(iocs),
            "filters": {"verdict": verdict, "source": source, "type": ioc_type}
        })

    # ── Scan VT single IOC ────────────────────────────────────
    @app.route("/api/v1/ioc/scan")
    def api_ioc_scan():
        value    = request.args.get('value','')
        ioc_type = request.args.get('type','ip')
        if not value:
            return jsonify({"error": "value required"}), 400

        result = _vt_scan(ioc_type, value)

        # Sauvegarder résultat
        with get_conn() as c:
            c.execute("""
                UPDATE ioc SET vt_malicious=?, vt_verdict=?, vt_score=?
                WHERE value=?
            """, (result.get('vt_malicious',0),
                  result.get('vt_verdict','UNKNOWN'),
                  result.get('vt_malicious',0), value))

        return jsonify({"value": value, "type": ioc_type, **result})

    # ── Batch VT scan ─────────────────────────────────────────
    @app.route("/api/v1/ioc/batch-scan", methods=["POST"])
    def api_ioc_batch_scan():
        limit = int((request.json or {}).get('limit', 10))
        import threading
        t = threading.Thread(target=_batch_vt_scan, args=(limit,), daemon=True)
        t.start()
        return jsonify({
            "status" : "started",
            "message": f"VT batch scan lancé pour {limit} IOC",
            "rate_limit": "4 req/min (plan gratuit VT)"
        })

    # ── Sources disponibles ───────────────────────────────────
    @app.route("/api/v1/ioc/sources")
    def api_ioc_sources():
        sources_info = {
            'Feodo-C2'        : {'name':'Feodo Tracker',     'url':'https://feodotracker.abuse.ch',    'type':'C2 IPs',      'update':'3h'},
            'CINS-Score'      : {'name':'CINS Army List',    'url':'https://cinsscore.com',             'type':'Malicious IPs','update':'3h'},
            'EmergingThreats' : {'name':'Emerging Threats',  'url':'https://rules.emergingthreats.net', 'type':'IDS IPs',     'update':'3h'},
            'URLhaus'         : {'name':'URLhaus',            'url':'https://urlhaus.abuse.ch',          'type':'Malicious URLs','update':'3h'},
            'Maltrail-CIRCL'  : {'name':'Maltrail (CIRCL)',  'url':'https://www.circl.lu',              'type':'Domains',     'update':'24h'},
            'KRVTZ-IDS'       : {'name':'KRVTZ IDS Alerts',  'url':'https://www.circl.lu',              'type':'IDS IPs',     'update':'24h'},
        }

        with get_conn() as c:
            db_sources = c.execute("""
                SELECT source, COUNT(*) as total,
                       SUM(CASE WHEN vt_verdict='MALICIOUS' THEN 1 ELSE 0 END) as malicious,
                       MAX(created_at) as last_update
                FROM ioc GROUP BY source
            """).fetchall()

        result = []
        for row in db_sources:
            src = row['source']
            info = sources_info.get(src, {'name': src, 'url':'', 'type':'Unknown', 'update':'?'})
            result.append({
                **info,
                "key"        : src,
                "total"      : row['total'],
                "malicious"  : row['malicious'],
                "last_update": row['last_update']
            })

        return jsonify({"sources": result, "total": len(result)})


    # ── Recherche IOC temps réel ─────────────────────────────
    @app.route("/api/v1/ioc/search")
    def api_ioc_search():
        """
        Recherche IOC en temps réel sur toutes les sources simultanément.
        Retourne résultats progressifs via JSON.
        """
        import concurrent.futures
        value    = request.args.get('value','').strip()
        ioc_type = request.args.get('type','auto')

        if not value or len(value) < 3:
            return jsonify({"error": "value must be at least 3 chars"}), 400

        # Auto-detect type
        if ioc_type == 'auto':
            import re
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', value):
                ioc_type = 'ip'
            elif value.startswith('http'):
                ioc_type = 'url'
            elif re.match(r'^[a-f0-9]{32,64}$', value):
                ioc_type = 'hash'
            else:
                ioc_type = 'domain'

        results = {
            "value"    : value,
            "type"     : ioc_type,
            "sources"  : {},
            "verdict"  : "UNKNOWN",
            "risk"     : "LOW",
            "summary"  : {}
        }

        # Vérifier dans notre DB locale d'abord
        with get_conn() as conn:
            local = conn.execute(
                "SELECT * FROM ioc WHERE value=? OR value LIKE ?",
                (value, f'%{value}%')
            ).fetchall()
        results['sources']['local_db'] = {
            "name"   : "Local DB (Feodo/CINS/URLhaus/CIRCL)",
            "found"  : len(local) > 0,
            "count"  : len(local),
            "data"   : [dict(r) for r in local[:5]],
            "status" : "✅ trouvé" if local else "⬜ non trouvé"
        }

        # Lancer toutes les sources en parallèle
        def check_vt():
            result = _vt_scan(ioc_type, value)
            return "virustotal", {
                "name"    : "VirusTotal",
                "found"   : result.get('vt_malicious',0) > 0,
                "verdict" : result.get('vt_verdict','UNKNOWN'),
                "engines" : result.get('vt_malicious',0),
                "country" : result.get('vt_country',''),
                "owner"   : result.get('vt_owner',''),
                "top_engines": result.get('vt_engines',[])[:5],
                "status"  : f"🔴 {result.get('vt_malicious',0)} engines" if result.get('vt_malicious',0) > 0 else "✅ clean"
            }

        def check_otx():
            if ioc_type not in ('ip','domain','url'):
                return "otx", {"name":"OTX AlienVault","found":False,"status":"⬜ type non supporté"}
            result = _otx_enrich(value) if ioc_type=='ip' else _otx_enrich_domain(value)
            return "otx", {
                "name"   : "AlienVault OTX",
                "found"  : result.get('otx_pulses',0) > 0,
                "pulses" : result.get('otx_pulses',0),
                "country": result.get('otx_country',''),
                "tags"   : result.get('otx_tags',[]),
                "role"   : result.get('otx_role',''),
                "status" : f"⚠️ {result.get('otx_pulses',0)} pulses" if result.get('otx_pulses',0) > 0 else "⬜ non trouvé"
            }

        def check_shodan():
            if ioc_type != 'ip':
                return "shodan", {"name":"Shodan InternetDB","found":False,"status":"⬜ IP uniquement"}
            result = _shodan_enrich(value)
            return "shodan", {
                "name"    : "Shodan InternetDB",
                "found"   : bool(result.get('shodan_ports')),
                "ports"   : result.get('shodan_ports',[]),
                "vulns"   : result.get('shodan_vulns',[]),
                "tags"    : result.get('shodan_tags',[]),
                "hostnames": result.get('shodan_hostnames',[]),
                "is_tor"  : result.get('is_tor',False),
                "status"  : f"⚠️ {len(result.get('shodan_ports',[]))} ports ouverts" if result.get('shodan_ports') else "⬜ non trouvé"
            }

        def check_misp():
            try:
                import urllib3
                urllib3.disable_warnings()
                import os
                MISP_URL = os.getenv('MISP_URL','https://localhost')
                MISP_KEY = os.getenv('MISP_KEY','')
                headers  = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}
                r = requests.post(f"{MISP_URL}/attributes/restSearch",
                    headers=headers, verify=False, timeout=8,
                    json={"value": value, "limit": 5, "returnFormat": "json"})
                attrs = r.json().get('response',{}).get('Attribute',[]) if r.status_code==200 else []
                return "misp", {
                    "name"    : "MISP Community",
                    "found"   : len(attrs) > 0,
                    "count"   : len(attrs),
                    "events"  : list(set(a.get('event_id') for a in attrs))[:3],
                    "to_ids"  : any(a.get('to_ids') for a in attrs),
                    "status"  : f"⚠️ trouvé dans {len(attrs)} events MISP" if attrs else "⬜ non trouvé"
                }
            except:
                return "misp", {"name":"MISP Community","found":False,"status":"❌ erreur"}

        def check_abuseipdb():
            if ioc_type != 'ip':
                return "abuseipdb", {"name":"AbuseIPDB","found":False,"status":"⬜ IP uniquement"}
            try:
                r = requests.get("https://api.abuseipdb.com/api/v2/check",
                    headers={"Accept":"application/json","Key":""},
                    params={"ipAddress": value, "maxAgeInDays": 90},
                    timeout=8)
                if r.status_code == 200:
                    d = r.json().get('data',{})
                    score = d.get('abuseConfidenceScore',0)
                    return "abuseipdb", {
                        "name"    : "AbuseIPDB",
                        "found"   : score > 0,
                        "score"   : score,
                        "country" : d.get('countryCode',''),
                        "reports" : d.get('totalReports',0),
                        "status"  : f"🔴 score {score}%" if score > 50 else f"⬜ score {score}%"
                    }
            except:
                pass
            return "abuseipdb", {"name":"AbuseIPDB","found":False,"status":"⬜ non disponible"}

        # Exécution parallèle
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(check_vt),
                executor.submit(check_otx),
                executor.submit(check_shodan),
                executor.submit(check_misp),
                executor.submit(check_abuseipdb),
            ]
            for future in concurrent.futures.as_completed(futures):
                try:
                    key, data = future.result(timeout=20)
                    results['sources'][key] = data
                except Exception as e:
                    pass

        # Calcul verdict global
        vt_data    = results['sources'].get('virustotal',{})
        otx_data   = results['sources'].get('otx',{})
        misp_data  = results['sources'].get('misp',{})
        shodan_data= results['sources'].get('shodan',{})

        mal_engines = vt_data.get('engines',0)
        otx_pulses  = otx_data.get('pulses',0)
        in_misp     = misp_data.get('found',False)
        in_local    = results['sources']['local_db']['found']

        if mal_engines > 10 or (mal_engines > 0 and in_misp):
            results['verdict'] = 'MALICIOUS'
            results['risk']    = 'CRITICAL'
        elif mal_engines > 3 or otx_pulses > 10:
            results['verdict'] = 'SUSPICIOUS'
            results['risk']    = 'HIGH'
        elif mal_engines > 0 or otx_pulses > 0 or in_local:
            results['verdict'] = 'POTENTIALLY_MALICIOUS'
            results['risk']    = 'MEDIUM'
        else:
            results['verdict'] = 'CLEAN'
            results['risk']    = 'LOW'

        results['summary'] = {
            "vt_engines"  : mal_engines,
            "otx_pulses"  : otx_pulses,
            "in_misp"     : in_misp,
            "in_local_db" : in_local,
            "shodan_ports": len(shodan_data.get('ports',[])),
            "is_tor"      : shodan_data.get('is_tor',False),
        }

        # Sauvegarder dans DB si nouveau
        with get_conn() as conn:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO ioc (type, value, source, ml_score, tlp, vt_verdict, vt_malicious)
                    VALUES (?, ?, 'user-search', 0.5, 'TLP:WHITE', ?, ?)
                """, (ioc_type, value,
                      vt_data.get('verdict','PENDING'),
                      mal_engines))
            except:
                pass

        return jsonify(results)

# ── Helpers privés ────────────────────────────────────────────
def _vt_scan(ioc_type: str, value: str) -> dict:
    """Scan VirusTotal."""
    try:
        if ioc_type in ('ip','ip-dst','ip-src','IPv4'):
            r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
                headers={"x-apikey": VT_KEY}, timeout=15)
        elif ioc_type == 'url':
            import base64
            uid = base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers={"x-apikey": VT_KEY}, timeout=15)
        else:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{value}",
                headers={"x-apikey": VT_KEY}, timeout=15)

        if r.status_code == 200:
            d     = r.json().get('data',{}).get('attributes',{})
            stats = d.get('last_analysis_stats',{})
            mal   = stats.get('malicious',0)
            return {
                "vt_malicious" : mal,
                "vt_suspicious": stats.get('suspicious',0),
                "vt_verdict"   : "MALICIOUS" if mal>3 else "SUSPICIOUS" if mal>0 else "CLEAN",
                "vt_country"   : d.get('country',''),
                "vt_owner"     : d.get('as_owner',''),
                "vt_engines"   : [k for k,v in d.get('last_analysis_results',{}).items()
                                   if v.get('category')=='malicious'][:8],
                "vt_score"     : mal,
            }
    except Exception as e:
        print(f"[VT] Error: {e}")
    return {}

def _otx_enrich_domain(domain: str) -> dict:
    """OTX enrichissement pour domaine."""
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            verify=False, timeout=12)
        if r.status_code == 200:
            d = r.json()
            pulses = d.get('pulse_info',{}).get('pulses',[])
            tags = []
            for p in pulses[:5]:
                tags.extend(p.get('tags',[])[:3])
            return {
                "otx_pulses": d.get('pulse_info',{}).get('count',0),
                "otx_tags"  : list(set(tags))[:6],
                "otx_role"  : _infer_role(tags),
            }
    except:
        pass
    return {}

def _otx_enrich(ip: str) -> dict:
    """AlienVault OTX enrichissement."""
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            verify=False, timeout=12)
        if r.status_code == 200:
            d = r.json()
            pulses = d.get('pulse_info',{}).get('pulses',[])
            tags   = []
            for p in pulses[:5]:
                tags.extend(p.get('tags',[])[:3])
            return {
                "otx_pulses" : d.get('pulse_info',{}).get('count',0),
                "otx_country": d.get('country_name',''),
                "otx_asn"    : d.get('asn',''),
                "otx_tags"   : list(set(tags))[:6],
                "otx_role"   : _infer_role(tags),
            }
    except:
        pass
    return {}

def _shodan_enrich(ip: str) -> dict:
    """Shodan InternetDB (gratuit, sans clé)."""
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 200:
            d = r.json()
            return {
                "shodan_ports"   : d.get('ports',[]),
                "shodan_vulns"   : d.get('vulns',[])[:5],
                "shodan_tags"    : d.get('tags',[]),
                "shodan_hostnames": d.get('hostnames',[])[:3],
                "is_tor"         : 'tor' in d.get('tags',[]),
                "is_cloud"       : 'cloud' in d.get('tags',[]),
            }
    except:
        pass
    return {}

def _infer_role(tags: list) -> str:
    t = ' '.join(tags).lower()
    if 'c2' in t or 'botnet' in t:    return 'C2'
    if 'scanner' in t or 'scan' in t: return 'Scanner'
    if 'exploit' in t:                return 'Exploiter'
    if 'tor' in t:                    return 'Anonymizer'
    return 'Threat Actor'

def _compute_risk(d: dict) -> str:
    if d.get('vt_malicious',0) > 10: return 'CRITICAL'
    if d.get('vt_malicious',0) > 3:  return 'HIGH'
    if d.get('vt_verdict') == 'SUSPICIOUS': return 'MEDIUM'
    return 'LOW'

def _batch_vt_scan(limit: int):
    with get_conn() as c:
        iocs = c.execute("""
            SELECT id, type, value FROM ioc
            WHERE vt_verdict IS NULL OR vt_verdict='PENDING'
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()

    print(f"[IOC API] VT batch scan: {len(iocs)} IOC")
    for ioc in iocs:
        result = _vt_scan(ioc['type'], ioc['value'])
        if result:
            with get_conn() as c:
                c.execute("""
                    UPDATE ioc SET vt_malicious=?, vt_verdict=?, vt_score=?
                    WHERE id=?
                """, (result.get('vt_malicious',0),
                      result.get('vt_verdict','UNKNOWN'),
                      result.get('vt_score',0), ioc['id']))
            print(f"  {ioc['value']} → {result.get('vt_verdict')} ({result.get('vt_malicious',0)} engines)")
        time.sleep(16)  # 4 req/min
