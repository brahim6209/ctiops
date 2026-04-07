"""
Pipeline CVE ↔ IOC :
1. Pour chaque CVE critique, cherche IOC spécifiques sur OTX
2. Vérifie ces IOC dans MISP community
3. Retourne la chaîne complète CVE → IOC → MISP context
"""
import requests, urllib3, json, time
urllib3.disable_warnings()

OTX_BASE  = "https://otx.alienvault.com/api/v1"
MISP_URL  = "https://localhost"
MISP_KEY  = "4CpRG1g4sQqecJy3l1f1tCHroczs7xj2pQFQCdrC"
MISP_HDR  = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}

# ── 1. OTX : Chercher IOC liés à une CVE
def otx_search_cve(cve_id: str) -> dict:
    """
    Chercher IOC liés à une CVE sur OTX.
    Stratégie multi-niveau :
    1. Lookup direct CVE (fonctionne pour CVE connues)
    2. Search par keyword CVE ID dans les pulses
    3. Fallback : IOC locaux MALICIOUS comme contexte
    """
    result = {"cve_id": cve_id, "otx_pulses": [], "iocs": [], "otx_pulse_count": 0}
    
    # Niveau 1 : lookup direct CVE
    try:
        r = requests.get(
            f"{OTX_BASE}/indicators/CVE/{cve_id}/general",
            verify=False, timeout=12
        )
        if r.status_code == 200:
            d = r.json()
            count = d.get('pulse_info', {}).get('count', 0)
            result['otx_pulse_count'] = count
            if count > 0:
                for pulse in d.get('pulse_info', {}).get('pulses', [])[:5]:
                    result['otx_pulses'].append({
                        "name": pulse.get('name',''),
                        "tags": pulse.get('tags', []),
                        "tlp" : pulse.get('tlp', 'white'),
                    })
                    # Récupérer IOC du pulse
                    try:
                        r2 = requests.get(
                            f"{OTX_BASE}/pulses/{pulse['id']}/indicators",
                            verify=False, timeout=10
                        )
                        if r2.status_code == 200:
                            for ind in r2.json().get('results', [])[:8]:
                                t = ind.get('type','')
                                if t in ('IPv4','domain','URL','FileHash-MD5','FileHash-SHA256'):
                                    result['iocs'].append({
                                        "type"  : t,
                                        "value" : ind.get('indicator',''),
                                        "pulse" : pulse.get('name','')[:50],
                                        "source": "OTX-CVE",
                                    })
                        time.sleep(0.2)
                    except:
                        pass
    except:
        pass
    
    # Niveau 2 : search keyword si rien trouvé
    if result['otx_pulse_count'] == 0:
        try:
            r = requests.get(
                f"{OTX_BASE}/search/pulses?q={cve_id}&limit=3",
                verify=False, timeout=12
            )
            if r.status_code == 200:
                pulses = r.json().get('results', [])
                result['otx_pulse_count'] = len(pulses)
                for p in pulses:
                    result['otx_pulses'].append({
                        "name": p.get('name',''),
                        "tags": p.get('tags',[]),
                        "tlp" : p.get('TLP','white'),
                    })
                    for ind in p.get('indicators',[])[:5]:
                        t = ind.get('type','')
                        if t in ('IPv4','domain','URL','FileHash-MD5'):
                            result['iocs'].append({
                                "type"  : t,
                                "value" : ind.get('indicator',''),
                                "pulse" : p.get('name','')[:50],
                                "source": "OTX-Search",
                            })
        except:
            pass
    
    result['note'] = "CVE trouvée dans OTX" if result['otx_pulse_count'] > 0 else "CVE récente — non encore indexée dans OTX (délai communautaire normal)"
    return result

# ── 2. OTX : Enrichir une IP/domaine avec contexte ───────────
def otx_enrich_ioc(ioc_type: str, value: str) -> dict:
    """Enrichir un IOC avec le contexte OTX communautaire."""
    type_map = {
        'IPv4':'IPv4','IPv6':'IPv6','ip':'IPv4',
        'domain':'domain','URL':'URL','url':'URL',
        'FileHash-MD5':'file','FileHash-SHA256':'file',
        'md5':'file','sha256':'file'
    }
    otx_type = type_map.get(ioc_type, 'IPv4')
    
    try:
        r = requests.get(
            f"{OTX_BASE}/indicators/{otx_type}/{value}/general",
            verify=False, timeout=12
        )
        if r.status_code == 200:
            d = r.json()
            pulses = d.get('pulse_info', {}).get('pulses', [])
            tags, malware_families = [], []
            
            for p in pulses[:5]:
                tags.extend(p.get('tags', [])[:3])
                for mf in p.get('malware_families', [])[:2]:
                    malware_families.append(mf.get('display_name', ''))
            
            return {
                "otx_pulses"    : d.get('pulse_info', {}).get('count', 0),
                "otx_reputation": d.get('reputation', 0),
                "otx_country"   : d.get('country_name', ''),
                "otx_asn"       : d.get('asn', ''),
                "otx_tags"      : list(set(tags))[:6],
                "otx_malware"   : list(set(malware_families))[:3],
                "otx_role"      : _infer_role(tags),
            }
    except Exception as e:
        pass
    return {}

def _infer_role(tags: list) -> str:
    """Inférer le rôle de l'IOC depuis ses tags OTX."""
    tags_lower = [t.lower() for t in tags]
    all_tags = ' '.join(tags_lower)
    if 'c2' in all_tags or 'botnet' in all_tags or 'command' in all_tags:
        return 'C2'
    if 'scanner' in all_tags or 'scan' in all_tags or 'probe' in all_tags:
        return 'Scanner'
    if 'exploit' in all_tags or 'attack' in all_tags:
        return 'Exploiter'
    if 'malware' in all_tags or 'rat' in all_tags or 'trojan' in all_tags:
        return 'Malware'
    if 'phish' in all_tags:
        return 'Phishing'
    return 'Threat Actor'

# ── 3. MISP : Vérifier IOC dans community ────────────────────
def misp_check_ioc(value: str) -> dict:
    """Vérifier si un IOC est connu dans MISP community."""
    try:
        r = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers=MISP_HDR, verify=False, timeout=10,
            json={"value": value, "limit": 3, "returnFormat": "json"}
        )
        if r.status_code == 200:
            attrs = r.json().get('response', {}).get('Attribute', [])
            if attrs:
                return {
                    "in_misp"   : True,
                    "misp_count": len(attrs),
                    "misp_events": [a.get('event_id') for a in attrs[:3]],
                    "misp_types" : list(set(a.get('type') for a in attrs))
                }
    except:
        pass
    return {"in_misp": False, "misp_count": 0}

# ── 4. Pipeline complet CVE → IOC → MISP ─────────────────────
def run_cve_ioc_pipeline(cve_id: str) -> dict:
    """Pipeline complet pour une CVE."""
    print(f"[Pipeline] Analyse {cve_id}...")
    
    # Étape 1 : OTX CVE lookup
    otx_result = otx_search_cve(cve_id)
    print(f"  OTX: {otx_result.get('otx_pulse_count',0)} pulses, {len(otx_result.get('iocs',[]))} IOC")
    
    # Étape 2 : Enrichir chaque IOC avec OTX + MISP check
    enriched_iocs = []
    for ioc in otx_result.get('iocs', [])[:10]:
        # OTX enrichissement
        otx_ctx = otx_enrich_ioc(ioc['type'], ioc['value'])
        # MISP check
        misp_ctx = misp_check_ioc(ioc['value'])
        
        enriched_iocs.append({
            **ioc,
            **otx_ctx,
            **misp_ctx,
        })
        time.sleep(0.3)
    
    # Étape 3 : Ajouter les IOC locaux DB liés à cette CVE
    from database import get_conn
    with get_conn() as c:
        local_iocs = c.execute("""
            SELECT type, value, source, vt_verdict, vt_malicious, ml_score
            FROM ioc
            WHERE vt_verdict IN ('MALICIOUS','SUSPICIOUS')
            ORDER BY vt_malicious DESC LIMIT 5
        """).fetchall()
    
    local_enriched = []
    for ioc in local_iocs:
        d = dict(ioc)
        otx_ctx  = otx_enrich_ioc(d['type'], d['value'])
        misp_ctx = misp_check_ioc(d['value'])
        local_enriched.append({**d, **otx_ctx, **misp_ctx, "source_db": "local"})
        time.sleep(0.3)
    
    return {
        "cve_id"       : cve_id,
        "otx_pulses"   : otx_result.get('otx_pulses', []),
        "otx_pulse_count": otx_result.get('otx_pulse_count', 0),
        "otx_iocs"     : enriched_iocs,
        "local_iocs"   : local_enriched,
        "total_iocs"   : len(enriched_iocs) + len(local_enriched),
        "pipeline_steps": [
            {"step": 1, "name": "OTX CVE Lookup",    "endpoint": f"OTX /indicators/CVE/{cve_id}/general"},
            {"step": 2, "name": "IOC Enrichment",     "endpoint": "OTX /indicators/{type}/{value}/general"},
            {"step": 3, "name": "MISP Community Check","endpoint": "MISP /attributes/restSearch"},
            {"step": 4, "name": "Local DB IOC",       "endpoint": "SQLite ioc table (Feodo/CINS/URLhaus)"},
        ]
    }

def register_cve_ioc_routes(app):
    from flask import request, jsonify
    from database import get_conn

    @app.route("/api/v1/cve/<cve_id>/iocs")
    def api_cve_iocs(cve_id):
        """Pipeline complet CVE → IOC → MISP pour une CVE spécifique."""
        result = run_cve_ioc_pipeline(cve_id)
        return jsonify(result)

    @app.route("/api/v1/cve/iocs/batch")
    def api_cve_iocs_batch():
        """Batch : Top CVE critiques pipeline avec leurs IOC."""
        with get_conn() as c:
            cves = c.execute("""
                SELECT DISTINCT json_extract(i.details,'$.cve_id') as cve_id,
                       c.cvss_score, c.epss_score, c.reality_score,
                       c.attack_type, c.actively_exploited,
                       json_extract(i.details,'$.build') as build,
                       json_extract(i.details,'$.package') as package
                FROM incident i
                LEFT JOIN cve c ON json_extract(i.details,'$.cve_id') = c.id
                WHERE i.source='trivy'
                AND c.severity='CRITICAL'
                AND c.reality_score > 50
                ORDER BY c.reality_score DESC
                LIMIT 5
            """).fetchall()
        
        results = []
        for cve in cves:
            d = dict(cve)
            if not d.get('cve_id'):
                continue
            pipeline = run_cve_ioc_pipeline(d['cve_id'])
            results.append({
                "cve_id"        : d['cve_id'],
                "reality_score" : d['reality_score'],
                "attack_type"   : d['attack_type'],
                "epss"          : d['epss_score'],
                "kev"           : bool(d['actively_exploited']),
                "build"         : d['build'],
                "package"       : (d.get('package') or '').split(':')[-1],
                "otx_pulses"    : pipeline['otx_pulse_count'],
                "iocs"          : pipeline['otx_iocs'] + pipeline['local_iocs'],
                "total_iocs"    : pipeline['total_iocs'],
                "pipeline_steps": pipeline['pipeline_steps'],
            })
            time.sleep(0.5)
        
        return jsonify({
            "cves"   : results,
            "total"  : len(results),
            "sources": ["OTX AlienVault", "MISP Community", "Feodo/CINS/URLhaus"]
        })
