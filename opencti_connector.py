"""opencti_connector.py — Push données vers OpenCTI (ou mock)"""
import os, requests, json
from dotenv import load_dotenv
from database import get_unpushed, mark_pushed
from stix_normalizer import cve_to_stix, ioc_to_stix

load_dotenv()
OPENCTI_URL   = os.getenv("OPENCTI_URL", "http://localhost:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")

def push_object(stix_json: str) -> bool:
    try:
        r = requests.post(
            f"{OPENCTI_URL}/graphql",
            json={"query": "mutation ImportStix($stixData: String!) { stixObjectOrStixRelationshipAdd(input: {stix: $stixData}) { id } }",
                  "variables": {"stixData": stix_json}},
            headers={"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"},
            timeout=10,
        )
        return r.status_code == 200
    except Exception as e:
        print(f"[OpenCTI] Erreur push: {e}")
        return False

def sync_all() -> int:
    print(f"[OpenCTI] Synchronisation vers {OPENCTI_URL}...")
    pushed = 0

    for row in get_unpushed("cve"):
        stix = cve_to_stix(dict(row))
        if push_object(stix["json"]):
            mark_pushed("cve", row["id"])
            pushed += 1
            print(f"[OpenCTI] CVE pushée : {row['id']}")

    for row in get_unpushed("ioc"):
        stix = ioc_to_stix(dict(row))
        if stix and push_object(stix["json"]):
            mark_pushed("ioc", row["id"])
            pushed += 1

    print(f"[OpenCTI] {pushed} objets synchronisés.")
    return pushed

if __name__ == "__main__":
    sync_all()
