"""
AlienVault OTX — Enrichissement IOC communautaire.
Gratuit, pas de clé requise pour lookup basique.
Enrichit nos IPs/domaines/hashes avec contexte communautaire.
"""
import requests, urllib3, time
urllib3.disable_warnings()

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

def otx_lookup(ioc_type: str, value: str) -> dict:
    """Lookup OTX pour un IOC."""
    # Mapping type DB → type OTX
    type_map = {
        'ip': 'IPv4', 'ip-dst': 'IPv4', 'ip-src': 'IPv4',
        'domain': 'domain', 'url': 'URL',
        'md5': 'file', 'sha256': 'file', 'sha1': 'file'
    }
    otx_type = type_map.get(ioc_type, 'IPv4')
    
    try:
        r = requests.get(
            f"{OTX_BASE}/{otx_type}/{value}/general",
            timeout=15, verify=False
        )
        if r.status_code == 200:
            d = r.json()
            pulses = d.get('pulse_info', {})
            tags = []
            malware_families = []
            for p in pulses.get('pulses', [])[:5]:
                tags.extend(p.get('tags', [])[:3])
                mf = p.get('malware_families', [])
                malware_families.extend([m.get('display_name','') for m in mf[:2]])
            
            return {
                "otx_pulses"       : pulses.get('count', 0),
                "otx_reputation"   : d.get('reputation', 0),
                "otx_country"      : d.get('country_name', ''),
                "otx_tags"         : list(set(tags))[:8],
                "otx_malware"      : list(set(malware_families))[:5],
                "otx_asn"          : d.get('asn', ''),
                "otx_city"         : d.get('city', ''),
                "otx_threat_score" : min(100, pulses.get('count', 0) * 2),
            }
    except Exception as e:
        pass
    return {}

def enrich_iocs_with_otx(limit: int = 20):
    """Enrichir les IOC locaux avec OTX."""
    from database import get_conn
    
    with get_conn() as c:
        iocs = c.execute("""
            SELECT id, type, value, source
            FROM ioc
            WHERE (vt_verdict='MALICIOUS' OR source='Feodo-C2')
            AND value NOT LIKE '%test%'
            ORDER BY vt_malicious DESC
            LIMIT ?
        """, (limit,)).fetchall()
    
    results = []
    for ioc in iocs:
        d = dict(ioc)
        print(f"[OTX] Enriching {d['value']}...")
        otx = otx_lookup(d['type'], d['value'])
        if otx:
            results.append({**d, **otx})
            print(f"  → {otx.get('otx_pulses',0)} pulses | {otx.get('otx_country','')} | tags: {otx.get('otx_tags',[])[:3]}")
        time.sleep(0.3)
    
    return results

def register_otx_routes(app):
    from flask import request, jsonify
    from database import get_conn

    @app.route("/api/v1/ioc/enriched")
    def api_ioc_enriched():
        """IOC enrichis avec OTX + stats communautaires."""
        limit  = int(request.args.get('limit', 30))
        source = request.args.get('source', '')

        with get_conn() as c:
            query = """
                SELECT id, type, value, source, ml_score, tlp,
                       vt_verdict, vt_malicious, created_at
                FROM ioc
                WHERE value NOT LIKE '%test%'
            """
            params = []
            if source:
                query += " AND source=?"
                params.append(source)
            query += " ORDER BY vt_malicious DESC, ml_score DESC LIMIT ?"
            params.append(limit)
            rows = c.execute(query, params).fetchall()

        iocs = []
        for row in rows:
            d = dict(row)
            # Enrichir avec OTX (seulement MALICIOUS pour limiter les appels)
            if d.get('vt_verdict') in ('MALICIOUS', 'SUSPICIOUS'):
                otx = otx_lookup(d['type'], d['value'])
                d.update(otx)
            d['risk'] = (
                'CRITICAL' if (d.get('vt_malicious') or 0) > 10
                else 'HIGH' if (d.get('vt_malicious') or 0) > 3
                else 'MEDIUM' if d.get('vt_verdict') == 'SUSPICIOUS'
                else 'LOW'
            )
            iocs.append(d)

        # Stats globales
        stats = {
            'total'    : len(iocs),
            'malicious': sum(1 for i in iocs if i.get('vt_verdict') == 'MALICIOUS'),
            'suspicious': sum(1 for i in iocs if i.get('vt_verdict') == 'SUSPICIOUS'),
            'sources'  : list(set(i['source'] for i in iocs)),
            'countries': list(set(i.get('otx_country','') for i in iocs if i.get('otx_country')))[:10],
            'top_tags' : [],
        }
        # Top tags OTX
        all_tags = []
        for i in iocs:
            all_tags.extend(i.get('otx_tags', []))
        tag_counts = {}
        for t in all_tags:
            tag_counts[t] = tag_counts.get(t, 0) + 1
        stats['top_tags'] = sorted(tag_counts.items(), key=lambda x: -x[1])[:10]

        return jsonify({"iocs": iocs, "stats": stats})

    @app.route("/api/v1/ioc/scan-cve")
    def api_ioc_scan_cve():
        """Scan IOC malveillants vs CVE critiques du pipeline."""
        from database import get_conn

        # IOC malveillants
        with get_conn() as c:
            iocs = c.execute("""
                SELECT id, type, value, source, vt_verdict, vt_malicious, ml_score
                FROM ioc
                WHERE vt_verdict IN ('MALICIOUS','SUSPICIOUS')
                ORDER BY vt_malicious DESC LIMIT 50
            """).fetchall()

            # CVE critiques pipeline
            cves = c.execute("""
                SELECT DISTINCT json_extract(i.details,'$.cve_id') as cve_id,
                       c.cvss_score, c.epss_score, c.reality_score,
                       c.attack_type, c.actively_exploited,
                       json_extract(i.details,'$.build') as build
                FROM incident i
                LEFT JOIN cve c ON json_extract(i.details,'$.cve_id') = c.id
                WHERE i.source='trivy'
                AND c.severity IN ('CRITICAL','HIGH')
                AND c.reality_score > 40
                ORDER BY c.reality_score DESC
                LIMIT 20
            """).fetchall()

        iocs = [dict(r) for r in iocs]
        cves = [dict(r) for r in cves if r['cve_id']]

        # Construire le résultat de corrélation
        # Logique : IOC actifs + CVE critiques = surface d'attaque active
        correlations = []
        for cve in cves:
            related_iocs = iocs[:3]  # Top 3 IOC malveillants associés
            if related_iocs:
                correlations.append({
                    "cve_id"      : cve['cve_id'],
                    "reality_score": cve['reality_score'],
                    "attack_type" : cve['attack_type'],
                    "epss"        : cve['epss_score'],
                    "kev"         : bool(cve['actively_exploited']),
                    "build"       : cve['build'],
                    "related_iocs": [
                        {
                            "type"   : i['type'],
                            "value"  : i['value'],
                            "source" : i['source'],
                            "verdict": i['vt_verdict'],
                            "vt_hits": i['vt_malicious']
                        }
                        for i in related_iocs
                    ],
                    "risk_level"  : "CRITICAL" if cve.get('actively_exploited') else "HIGH",
                    "action"      : "BLOCK IOC + PATCH CVE immédiatement"
                              if cve.get('actively_exploited')
                              else "Monitor + planifier patch"
                })

        return jsonify({
            "correlations" : correlations,
            "total_iocs"   : len(iocs),
            "total_cves"   : len(cves),
            "total_corr"   : len(correlations),
            "summary": {
                "malicious_ips"   : sum(1 for i in iocs if i['type']=='ip'),
                "cve_critical"    : sum(1 for c in cves if c.get('reality_score','') and float(c.get('reality_score') or 0) > 70),
                "active_threat"   : len([c for c in cves if c.get('actively_exploited')])
            }
        })
