"""
misp_connector.py — Connecteur MISP réel (PyMISP)
Push automatique : CVE + IOC + Incidents → MISP avec TLP + MITRE ATT&CK
"""
import os, urllib3
urllib3.disable_warnings()

from pymisp import PyMISP, MISPEvent, MISPAttribute
from dotenv import load_dotenv
from database import get_conn

load_dotenv('/home/br1kx/cti/ctiops/.env')

MISP_URL  = os.getenv("MISP_URL", "https://localhost")
MISP_KEY  = os.getenv("MISP_KEY", "ctiprojectapikey1234567890abcdef12345678")
MISP_CERT = os.getenv("MISP_VERIFYCERT", "False").lower() != "true"

# TLP tag mapping
TLP_TAGS = {
    "TLP:WHITE": "tlp:white",
    "TLP:AMBER": "tlp:amber",
    "TLP:RED":   "tlp:red",
}

# CVSS → threat level MISP (1=High, 2=Medium, 3=Low, 4=Undefined)
def cvss_to_threat(score):
    if score is None: return 4
    s = float(score)
    if s >= 9.0: return 1
    if s >= 7.0: return 2
    if s >= 4.0: return 3
    return 4


def get_misp():
    return PyMISP(MISP_URL, MISP_KEY, False)


# ─────────────────────────────────────────
# PUSH CVE → MISP Events
# ─────────────────────────────────────────

def get_tlp_for_cve(cve: dict) -> str:
    """TLP selon Reality Score et exploitation active."""
    reality = float(cve.get('reality_score') or 0)
    active  = bool(cve.get('actively_exploited'))
    cvss    = float(cve.get('cvss_score') or 0)
    if reality > 80 or active or cvss >= 9.0:
        return 'TLP:AMBER'
    return 'TLP:WHITE'

def get_distribution_for_tlp(tlp: str) -> int:
    return {'TLP:RED':0,'TLP:AMBER':1,'TLP:WHITE':3}.get(tlp, 1)

def push_cves(limit=50) -> int:
    """Push les CVE critiques/high vers MISP."""
    misp = get_misp()
    with get_conn() as c:
        cves = c.execute(
            "SELECT * FROM cve WHERE severity IN ('CRITICAL','HIGH') "
            "AND pushed_opencti=0 ORDER BY cvss_score DESC LIMIT ?",
            (limit,)
        ).fetchall()

    count = 0
    for cve in cves:
        try:
            event = MISPEvent()
            event.info        = f"{cve['id']} — {(cve['description'] or '')[:100]}"
            event.distribution = 0
            event.threat_level_id = cvss_to_threat(cve['cvss_score'])
            event.analysis    = 1

            # Tag TLP
            tlp = cve['tlp'] or 'TLP:WHITE'
            event.add_tag(TLP_TAGS.get(tlp, 'tlp:white'))
            event.add_tag('cloud-security')
            event.add_tag('cve')

            # Attributs
            event.add_attribute('vulnerability', cve['id'],
                comment=f"CVSS: {cve['cvss_score']} | {cve['severity']}")

            if cve['description']:
                event.add_attribute('comment', cve['description'][:1000],
                    category='External analysis')

            # NVD reference
            event.add_attribute('url',
                f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                category='External analysis')

            e = misp.add_event(event, pythonify=True)

            # Marquer comme pushé
            with get_conn() as c:
                c.execute("UPDATE cve SET pushed_opencti=1 WHERE id=?", (cve['id'],))

            print(f"[MISP] CVE pushée : {cve['id']} → Event #{e.id}")
            count += 1

        except Exception as ex:
            print(f"[MISP] Erreur CVE {cve['id']}: {ex}")

    print(f"[MISP] {count} CVE pushées vers MISP")
    return count


# ─────────────────────────────────────────
# PUSH IOC → MISP Events
# ─────────────────────────────────────────

IOC_TYPE_MAP = {
    "ip":     "ip-dst",
    "domain": "domain",
    "hash":   "sha256",
    "url":    "url",
    "secret": "comment",
}

def push_iocs(limit=30) -> int:
    """Push les IOC malveillants vers MISP."""
    misp = get_misp()
    with get_conn() as c:
        iocs = c.execute(
            "SELECT i.*, e.score FROM ioc i "
            "LEFT JOIN enrichment e ON i.value=e.ioc_value "
            "WHERE i.pushed_opencti=0 "
            "ORDER BY i.created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()

    if not iocs:
        print("[MISP] Aucun IOC à pusher")
        return 0

    # Un seul event pour tous les IOC
    event = MISPEvent()
    event.info = "CTI Cloud-Native — IOC malveillants cloud"
    event.distribution = 0
    event.threat_level_id = 2
    event.analysis = 1
    event.add_tag('tlp:amber')
    event.add_tag('cloud-security')
    event.add_tag('ioc')

    count = 0
    ioc_ids = []
    for ioc in iocs:
        try:
            misp_type = IOC_TYPE_MAP.get(ioc['type'], 'comment')
            score = ioc['score'] or 0
            comment = f"Source: {ioc['source']} | VT Score: {score:.0f}%" if score else f"Source: {ioc['source']}"

            attr = event.add_attribute(
                misp_type,
                ioc['value'][:500],
                category='Network activity' if ioc['type'] in ('ip','domain','url') else 'Payload delivery',
                comment=comment,
                to_ids=score > 50
            )

            tlp = ioc['tlp'] if ioc['tlp'] else 'TLP:WHITE'
            attr.add_tag(TLP_TAGS.get(tlp, 'tlp:white'))

            ioc_ids.append(ioc['value'])
            count += 1
        except Exception as ex:
            print(f"[MISP] Erreur IOC {ioc['value'][:30]}: {ex}")

    try:
        e = misp.add_event(event, pythonify=True)
        print(f"[MISP] Event IOC créé #{e.id} avec {count} IOC")

        # Marquer comme pushés
        with get_conn() as c:
            for val in ioc_ids:
                c.execute("UPDATE ioc SET pushed_opencti=1 WHERE value=?", (val,))
    except Exception as ex:
        print(f"[MISP] Erreur création event IOC: {ex}")

    return count


# ─────────────────────────────────────────
# PUSH INCIDENTS → MISP Events
# ─────────────────────────────────────────

SEV_TO_THREAT = {
    "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4
}

def get_tlp_for_incident(inc: dict) -> str:
    """Déterminer le TLP selon le type d'incident.
    
    Politique :
    - Secret compromis    → TLP:RED   (DevOps uniquement)
    - Incident CI/CD      → TLP:AMBER (DevOps + SOC)
    - Attaque cloud       → TLP:AMBER (Cloud + SOC)
    """
    source = inc.get('source','')
    etype  = inc.get('event_type','')
    sev    = inc.get('severity','')

    # Secrets exposés → TLP:RED (jamais partagé hors org)
    if source == 'gitleaks' or 'secret' in etype.lower():
        return 'TLP:RED'

    # Incidents critiques pipeline → TLP:AMBER
    if sev in ('CRITICAL','HIGH') or source in ('trivy','owasp'):
        return 'TLP:AMBER'

    return 'TLP:AMBER'  # Par défaut AMBER pour incidents

def push_incidents(limit=20) -> int:
    """Push les incidents CI/CD critiques vers MISP."""
    misp = get_misp()
    with get_conn() as c:
        incs = c.execute(
            "SELECT * FROM incident WHERE pushed_opencti=0 "
            "AND severity IN ('CRITICAL','HIGH') "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()

    count = 0
    for inc in incs:
        try:
            event = MISPEvent()
            event.info = (
                f"CI/CD Incident: {inc['event_type']} — "
                f"{inc['repo']} [{inc['severity']}]"
            )
            event.distribution = 0
            event.threat_level_id = SEV_TO_THREAT.get(inc['severity'], 4)
            event.analysis = 1

            # Tags
            tlp = get_tlp_for_incident(dict(inc))
            event.distribution = get_distribution_for_tlp(tlp)
            event.add_tag(TLP_TAGS.get(tlp, 'tlp:white'))
            if tlp == 'TLP:RED':
                event.add_tag('cti:audience=DevOps-only')
            elif tlp == 'TLP:AMBER':
                event.add_tag('cti:audience=DevOps+SOC')
            event.add_tag('cicd-security')
            event.add_tag('cloud-security')
            if inc['mitre_id']:
                event.add_tag(f"mitre-attack:{inc['mitre_id']}")

            # Attributs
            if inc['repo']:
                event.add_attribute('github-repository', inc['repo'],
                    category='External analysis')
            if inc['actor']:
                event.add_attribute('text', f"Actor: {inc['actor']}",
                    category='Attribution')

            event.add_attribute('comment',
                f"Type: {inc['event_type']}\n"
                f"Source: {inc['source']}\n"
                f"MITRE: {inc['mitre_id']} — {inc['mitre_name']}\n"
                f"ML Severity: {inc['ml_severity']}\n"
                f"Anomaly Score: {inc['anomaly_score']}",
                category='Other')

            e = misp.add_event(event, pythonify=True)

            with get_conn() as c2:
                c2.execute(
                    "UPDATE incident SET pushed_opencti=1 WHERE id=?",
                    (inc['id'],)
                )

            print(f"[MISP] Incident pushé : #{inc['id']} {inc['event_type']} → Event #{e.id}")
            count += 1

        except Exception as ex:
            print(f"[MISP] Erreur incident #{inc['id']}: {ex}")

    print(f"[MISP] {count} incidents pushés vers MISP")
    return count


# ─────────────────────────────────────────
# SYNC COMPLÈTE
# ─────────────────────────────────────────

def sync_all() -> int:
    """Synchronisation complète vers MISP."""
    print("\n" + "="*50)
    print("  MISP Sync — CVE + IOC + Incidents")
    print("="*50)

    total = 0
    total += push_cves(limit=30)
    total += push_iocs(limit=20)
    total += push_incidents(limit=10)

    print(f"\n[MISP] Sync terminée — {total} objets pushés")
    return total


if __name__ == "__main__":
    from database import init_db
    init_db()
    sync_all()
