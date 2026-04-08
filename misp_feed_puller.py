"""
MISP Feed Puller — Pull les données MISP vers notre plateforme.
Récupère : CVE events, IOC attributs, incidents pipeline.
"""
import requests, urllib3, os
from dotenv import load_dotenv
from database import get_conn

urllib3.disable_warnings()
load_dotenv('/home/br1kx/cti/ctiops/.env')

MISP_URL = os.getenv('MISP_URL', 'https://localhost')
MISP_KEY = os.getenv('MISP_KEY')
HDR = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}

def pull_misp_stats() -> dict:
    """Stats globales MISP pour le dashboard."""
    try:
        # Total events
        r = requests.post(f"{MISP_URL}/events/restSearch",
            headers=HDR, verify=False,
            json={"limit": 1000, "metadata": True})
        events = r.json().get('response', [])

        # Compter par TLP
        tlp_dist = {"TLP:RED": 0, "TLP:AMBER": 0, "TLP:WHITE": 0}
        critical = 0
        cve_events = 0
        pipeline_events = 0
        top_tags = {}
        mitre_counts = {}

        for e in events:
            ev = e.get('Event', {})
            tags = [t.get('Tag',{}).get('name','') for t in ev.get('Tag',[])]
            info = ev.get('info', '')
            threat = int(ev.get('threat_level_id', 4))

            # TLP
            for tag in tags:
                if tag == 'tlp:red':   tlp_dist['TLP:RED'] += 1
                elif tag == 'tlp:amber': tlp_dist['TLP:AMBER'] += 1
                elif tag == 'tlp:white': tlp_dist['TLP:WHITE'] += 1

            # Critical
            if threat == 1: critical += 1

            # Type
            if info.startswith('CVE-'): cve_events += 1
            if 'pipeline' in info.lower() or 'build' in info.lower() or 'secret' in info.lower():
                pipeline_events += 1

            # Tags
            for tag in tags:
                if not tag.startswith('tlp:'):
                    top_tags[tag] = top_tags.get(tag, 0) + 1

            # MITRE
            for tag in tags:
                if tag.startswith('mitre-attack:'):
                    t = tag.replace('mitre-attack:', '')
                    mitre_counts[t] = mitre_counts.get(t, 0) + 1

        top_tags_sorted = sorted(top_tags.items(), key=lambda x: -x[1])[:8]
        top_mitre = sorted(mitre_counts.items(), key=lambda x: -x[1])[:5]

        return {
            "total_events"    : len(events),
            "critical_events" : critical,
            "cve_events"      : cve_events,
            "pipeline_events" : pipeline_events,
            "tlp_distribution": tlp_dist,
            "top_tags"        : [{"tag": t, "count": c} for t,c in top_tags_sorted],
            "top_mitre"       : [{"technique": t, "count": c} for t,c in top_mitre],
        }
    except Exception as e:
        print(f"[MISP Pull] Error stats: {e}")
        return {}

def pull_misp_iocs(limit=50) -> list:
    """Pull les IOC depuis MISP vers notre DB."""
    try:
        r = requests.post(f"{MISP_URL}/attributes/restSearch",
            headers=HDR, verify=False,
            json={
                "type": ["ip-dst", "ip-src", "domain", "url", "md5", "sha256"],
                "to_ids": True,
                "limit": limit,
                "returnFormat": "json"
            })
        attrs = r.json().get('response', {}).get('Attribute', [])
        added = 0
        with get_conn() as c:
            for attr in attrs:
                ioc_type = attr.get('type','')
                value    = attr.get('value','')
                if not value:
                    continue
                # Mapper type MISP → type DB
                db_type = {
                    'ip-dst':'ip','ip-src':'ip',
                    'domain':'domain','url':'url',
                    'md5':'hash','sha256':'hash'
                }.get(ioc_type, ioc_type)

                try:
                    c.execute("""
                        INSERT OR IGNORE INTO ioc
                        (type, value, source, ml_score, tlp, vt_verdict)
                        VALUES (?, ?, 'MISP-Pull', 0.5, 'TLP:WHITE', 'PENDING')
                    """, (db_type, value))
                    added += 1
                except:
                    pass
        print(f"[MISP Pull] {added} IOC importés depuis MISP")
        return attrs
    except Exception as e:
        print(f"[MISP Pull] Error IOC: {e}")
        return []

def pull_misp_cve_events(limit=20) -> list:
    """Pull les CVE events MISP avec TLP:AMBER vers notre plateforme."""
    try:
        r = requests.post(f"{MISP_URL}/events/restSearch",
            headers=HDR, verify=False,
            json={"tag": "tlp:amber", "limit": limit, "metadata": False})
        events = r.json().get('response', [])
        results = []
        for e in events:
            ev = e.get('Event', {})
            info = ev.get('info', '')
            if not info.startswith('CVE-'):
                continue
            cve_id = info.split(' ')[0]
            tags = [t.get('Tag',{}).get('name','') for t in ev.get('Tag',[])]
            attrs = ev.get('Attribute', [])

            results.append({
                "event_id"    : ev.get('id'),
                "cve_id"      : cve_id,
                "info"        : info,
                "tlp"         : "TLP:AMBER",
                "threat_level": ev.get('threat_level_id'),
                "date"        : ev.get('date'),
                "tags"        : tags,
                "attr_count"  : len(attrs),
            })
        return results
    except Exception as e:
        print(f"[MISP Pull] Error CVE: {e}")
        return []

def register_misp_pull_routes(app):
    from flask import request, jsonify

    @app.route("/api/v1/misp/feed")
    def api_misp_feed():
        """Stats MISP pour le dashboard — pull depuis MISP local."""
        stats = pull_misp_stats()
        return jsonify(stats)

    @app.route("/api/v1/misp/pull-iocs", methods=["POST"])
    def api_misp_pull_iocs():
        """Pull IOC depuis MISP vers notre DB."""
        limit = int((request.json or {}).get('limit', 50))
        attrs = pull_misp_iocs(limit)
        return jsonify({"pulled": len(attrs), "source": "MISP local"})

    @app.route("/api/v1/misp/amber-events")
    def api_misp_amber():
        """CVE events TLP:AMBER depuis MISP."""
        limit = int(request.args.get('limit', 20))
        events = pull_misp_cve_events(limit)
        return jsonify({"events": events, "total": len(events)})
