"""
misp_auto_sync.py — Synchronisation automatique CTI → MISP
Appelé automatiquement après chaque collecte NVD et chaque rapport DevSecOps
"""
import os, datetime, json, urllib3
urllib3.disable_warnings()

from pymisp import PyMISP, MISPEvent, MISPAttribute
from dotenv import load_dotenv
from database import get_conn

load_dotenv()

MISP_URL  = os.getenv("MISP_URL", "https://localhost")
MISP_KEY  = os.getenv("MISP_KEY", "")
MISP_CERT = False

def get_misp():
    return PyMISP(MISP_URL, MISP_KEY, MISP_CERT)

# ── PUSH CVE CRITIQUES → MISP ─────────────────────────────────────
def push_critical_cves(limit=20):
    """Push CVE CRITICAL/HIGH non encore pushées vers MISP."""
    misp = get_misp()
    pushed = 0
    errors = 0

    with get_conn() as c:
        cves = c.execute("""
            SELECT id, description, cvss_score, severity, epss_score,
                   has_exploit, actively_exploited, exploit_source
            FROM cve
            WHERE severity IN ('CRITICAL','HIGH')
            AND (pushed_opencti = 0 OR pushed_opencti IS NULL)
            ORDER BY
                CASE severity WHEN 'CRITICAL' THEN 2 WHEN 'HIGH' THEN 1 END DESC,
                COALESCE(epss_score, 0) DESC
            LIMIT ?
        """, (limit,)).fetchall()

    print(f"[MISP Sync] {len(cves)} CVE à pusher...")

    for cve in cves:
        d = dict(cve)
        try:
            event = MISPEvent()
            event.info = f"{d['id']} — {(d['description'] or '')[:80]}"
            event.threat_level_id = 1 if d['severity'] == 'CRITICAL' else 2
            event.analysis = 2  # Completed
            event.distribution = 0  # Your org only

            # Tags TLP + MITRE
            event.add_tag('tlp:amber')
            event.add_tag(f"cti:severity={d['severity']}")
            if d.get('has_exploit'):
                event.add_tag('cti:has-exploit')
                event.add_tag('mitre-attack:T1190')
            if d.get('actively_exploited'):
                event.add_tag('tlp:red')
                event.add_tag('cti:actively-exploited')
                event.add_tag('cisa:kev')

            # Attributes
            event.add_attribute('vulnerability', d['id'],
                comment=f"CVSS: {d['cvss_score']} | EPSS: {d.get('epss_score',0):.3f}")

            if d.get('cvss_score'):
                event.add_attribute('float', str(d['cvss_score']),
                    category='External analysis', comment='CVSS Score')

            if d.get('epss_score'):
                event.add_attribute('float', str(round(d['epss_score']*100, 1)),
                    category='External analysis', comment='EPSS % exploitation probability')

            if d.get('exploit_source'):
                event.add_attribute('text', str(d['exploit_source']),
                    category='External analysis', comment='Exploit source')

            # Push
            result = misp.add_event(event)
            if hasattr(result, 'id'):
                # Marquer comme pushé en DB
                with get_conn() as c:
                    c.execute("UPDATE cve SET pushed_opencti=1 WHERE id=?", (d['id'],))
                pushed += 1
                print(f"[MISP] Pushé: {d['id']} (MISP event #{result.id})")
            else:
                errors += 1

        except Exception as e:
            errors += 1
            print(f"[MISP] Erreur {d['id']}: {e}")

    print(f"[MISP Sync] CVE: {pushed} pushées, {errors} erreurs")
    return {"pushed": pushed, "errors": errors, "type": "cve"}


# ── PUSH INCIDENTS DEVSECOPS → MISP ──────────────────────────────
def push_devsecops_incidents(limit=30):
    """Push les incidents DevSecOps (GitLeaks, Trivy) vers MISP."""
    misp = get_misp()
    pushed = 0
    errors = 0

    with get_conn() as c:
        incidents = c.execute("""
            SELECT id, event_type, source, severity, repo,
                   mitre_id, details, created_at
            FROM incident
            WHERE severity IN ('CRITICAL','HIGH')
            AND (pushed_opencti = 0 OR pushed_opencti IS NULL)
            ORDER BY
                CASE severity WHEN 'CRITICAL' THEN 2 WHEN 'HIGH' THEN 1 END DESC,
                created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()

    print(f"[MISP Sync] {len(incidents)} incidents à pusher...")

    # Grouper par source pour créer un event par scanner
    by_source = {}
    for inc in incidents:
        d = dict(inc)
        src = d['source']
        if src not in by_source:
            by_source[src] = []
        by_source[src].append(d)

    for source, incs in by_source.items():
        try:
            event = MISPEvent()
            event.info = f"DevSecOps Scan — {source.upper()} — {incs[0].get('repo','unknown')}"
            event.threat_level_id = 1 if any(i['severity']=='CRITICAL' for i in incs) else 2
            event.analysis = 2
            event.distribution = 0

            event.add_tag('tlp:amber')
            event.add_tag(f"cti:scanner={source}")
            event.add_tag('cti:devsecops')

            critical_count = sum(1 for i in incs if i['severity'] == 'CRITICAL')
            high_count = sum(1 for i in incs if i['severity'] == 'HIGH')

            event.add_attribute('text',
                f"{len(incs)} findings: {critical_count} CRITICAL, {high_count} HIGH",
                category='External analysis',
                comment=f'Scanner: {source}')

            for inc in incs[:10]:  # Max 10 par event
                try:
                    details = json.loads(inc.get('details') or '{}')
                except:
                    details = {}

                mitre = inc.get('mitre_id', 'T1190')
                event.add_tag(f"mitre-attack:{mitre}")

                if source == 'gitleaks':
                    rule = details.get('rule_id', 'secret')
                    file = details.get('file', '')
                    hint = details.get('secret_hint', '***')
                    event.add_attribute('text',
                        f"SECRET: {rule} in {file} — hint: {hint}",
                        category='Payload delivery',
                        comment=f"Entropy: {details.get('entropy', 0)}")

                elif source == 'trivy':
                    cve_id = details.get('cve_id', '')
                    pkg = details.get('package', '')
                    if cve_id:
                        event.add_attribute('vulnerability', cve_id,
                            comment=f"Package: {pkg} | Score: {details.get('ml_score', 0)}")

                elif source == 'owasp':
                    cve_id = details.get('cve_id', '')
                    if cve_id:
                        event.add_attribute('vulnerability', cve_id,
                            comment=f"Package: {details.get('package', '')}")

            result = misp.add_event(event)
            if hasattr(result, 'id'):
                inc_ids = [i['id'] for i in incs]
                with get_conn() as c:
                    for iid in inc_ids:
                        c.execute("UPDATE incident SET pushed_opencti=1 WHERE id=?", (iid,))
                pushed += len(incs)
                print(f"[MISP] Pushé: {source} — {len(incs)} incidents (MISP #{result.id})")
            else:
                errors += 1

        except Exception as e:
            errors += 1
            print(f"[MISP] Erreur {source}: {e}")

    print(f"[MISP Sync] Incidents: {pushed} pushés, {errors} erreurs")
    return {"pushed": pushed, "errors": errors, "type": "incidents"}


# ── SYNC COMPLÈTE ─────────────────────────────────────────────────
def full_sync():
    """Synchronisation complète CTI → MISP."""
    print(f"\n[MISP Auto-Sync] Démarrage — {datetime.datetime.now().isoformat()}")
    results = {}
    try:
        results['cve'] = push_critical_cves(limit=20)
    except Exception as e:
        results['cve'] = {'error': str(e)}
        print(f"[MISP] Erreur CVE sync: {e}")
    try:
        results['incidents'] = push_devsecops_incidents(limit=30)
    except Exception as e:
        results['incidents'] = {'error': str(e)}
        print(f"[MISP] Erreur incidents sync: {e}")
    total = sum(r.get('pushed', 0) for r in results.values() if isinstance(r, dict))
    print(f"[MISP Auto-Sync] Terminé — {total} éléments pushés\n")
    return results


if __name__ == '__main__':
    full_sync()
