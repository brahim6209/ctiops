"""misp_feed.py — Feed retour MISP → Dashboard"""
import os, urllib3
urllib3.disable_warnings()
from pymisp import PyMISP
from dotenv import load_dotenv
from collections import Counter

load_dotenv()

MISP_URL = os.getenv("MISP_URL", "https://localhost")
MISP_KEY = os.getenv("MISP_KEY", "ctiprojectapikey1234567890abcdef12345678")

def get_misp():
    return PyMISP(MISP_URL, MISP_KEY, False)

def _mitre_label(tech):
    labels = {
        "T1552.001":"Credentials In Files","T1552":"Unsecured Credentials",
        "T1078":"Valid Accounts","T1499":"Endpoint DoS",
        "T1195":"Supply Chain Compromise","T1195.002":"Software Supply Chain",
        "T1548":"Abuse Elevation Control","T1190":"Exploit Public-Facing App",
        "T1071":"App Layer Protocol",
    }
    return labels.get(tech, tech)

def get_misp_intelligence():
    misp = get_misp()
    result = {"total_events":0,"cve_events":[],"incident_events":[],
              "ioc_events":[],"mitre_techniques":[],"tlp_distribution":{},
              "top_tags":[],"summary":{}}
    try:
        events = misp.search(controller='events', limit=100, pythonify=True)
        result["total_events"] = len(events)
        tag_counter = Counter()
        tlp_counter = Counter()
        mitre_counter = Counter()
        for event in events:
            tags = [t.name for t in event.tags]
            for tag in tags:
                tag_counter[tag] += 1
                if tag.startswith('tlp:'): tlp_counter[tag] += 1
                if tag.startswith('mitre-attack:'):
                    mitre_counter[tag.replace('mitre-attack:', '')] += 1
            info = event.info or ''
            edata = {"id":event.id,"info":info[:80],"tags":tags,
                     "attr_count":len(event.attributes or []),
                     "date":str(event.date) if event.date else '',
                     "threat_level":str(event.threat_level_id)}
            if 'cve' in tags or info.startswith('CVE-'):
                edata["cve_id"] = info.split(' — ')[0] if ' — ' in info else info[:20]
                for a in (event.attributes or []):
                    if a.type=='vulnerability': edata["cve_id"] = a.value
                result["cve_events"].append(edata)
            elif 'cicd-security' in tags:
                edata["mitre"] = next((t.replace('mitre-attack:','') for t in tags if t.startswith('mitre-attack:')), None)
                for a in (event.attributes or []):
                    if a.type=='github-repository': edata["repo"] = a.value
                result["incident_events"].append(edata)
            elif 'ioc' in tags:
                edata["iocs"] = [{"type":a.type,"value":a.value[:50]}
                                  for a in (event.attributes or [])
                                  if a.type in ('ip-dst','domain','sha256','url')]
                result["ioc_events"].append(edata)
        result["tlp_distribution"] = dict(tlp_counter)
        result["top_tags"] = [{"tag":t,"count":c} for t,c in tag_counter.most_common(10) if not t.startswith('tlp:')]
        result["mitre_techniques"] = [{"technique":t,"count":c,"label":_mitre_label(t)} for t,c in mitre_counter.most_common(10)]
        result["summary"] = {
            "total_events":    len(events),
            "cve_events":      len(result["cve_events"]),
            "incident_events": len(result["incident_events"]),
            "ioc_events":      len(result["ioc_events"]),
            "critical_events": sum(1 for e in events if str(e.threat_level_id)=='1'),
            "tlp_red_count":   tlp_counter.get('tlp:red',0),
            "tlp_amber_count": tlp_counter.get('tlp:amber',0),
            "top_mitre":       mitre_counter.most_common(1)[0][0] if mitre_counter else None,
        }
    except Exception as e:
        result["error"] = str(e)
    return result

def get_misp_cve_details(cve_id):
    misp = get_misp()
    try:
        events = misp.search(controller='events', value=cve_id, pythonify=True)
        if not events: return {"found":False,"cve_id":cve_id}
        e = events[0]
        return {"found":True,"cve_id":cve_id,"misp_id":e.id,
                "tags":[t.name for t in e.tags],
                "threat_level":str(e.threat_level_id),
                "attributes":[{"type":a.type,"value":a.value[:100]} for a in (e.attributes or [])],
                "date":str(e.date) if e.date else ''}
    except Exception as ex:
        return {"found":False,"error":str(ex)}

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  MISP Intelligence Feed")
    print("="*55)
    intel = get_misp_intelligence()
    s = intel["summary"]
    print(f"\nRésumé MISP :")
    print(f"  Total events     : {s.get('total_events',0)}")
    print(f"  Events CVE       : {s.get('cve_events',0)}")
    print(f"  Events Incidents : {s.get('incident_events',0)}")
    print(f"  Events IOC       : {s.get('ioc_events',0)}")
    print(f"  TLP:RED          : {s.get('tlp_red_count',0)}")
    print(f"  TLP:AMBER        : {s.get('tlp_amber_count',0)}")
    print(f"  Top technique    : {s.get('top_mitre','N/A')}")
    print(f"\nTop techniques MITRE ATT&CK :")
    for m in intel["mitre_techniques"][:5]:
        print(f"  {m['technique']:12} {m['label']:30} x{m['count']}")
    print(f"\nTop tags MISP :")
    for t in intel["top_tags"][:5]:
        print(f"  {t['tag']:30} x{t['count']}")
    print(f"\nIncidents CI/CD dans MISP :")
    for e in intel["incident_events"][:3]:
        print(f"  Event #{e['id']}: {e['info'][:60]}")
        print(f"    MITRE: {e.get('mitre','—')} | Tags: {e['tags']}")
