"""stix_normalizer.py — Normalisation STIX 2.1 + TLP"""
import json
from datetime import datetime, timezone
from stix2 import Vulnerability, Indicator, Bundle, ExternalReference

TLP_COLORS = {
    "TLP:WHITE": "white", "TLP:GREEN": "green",
    "TLP:AMBER": "amber", "TLP:RED":   "red",
}

def cve_to_stix(cve: dict) -> dict:
    vuln = Vulnerability(
        name=cve["id"],
        description=(cve.get("description") or "")[:500],
        external_references=[ExternalReference(
            source_name="NVD", external_id=cve["id"],
            url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
        )],
        custom_properties={
            "x_cvss_score":  cve.get("cvss_score"),
            "x_severity":    cve.get("severity"),
            "x_tlp":         cve.get("tlp", "TLP:WHITE"),
        }
    )
    return {"stix_id": vuln.id, "object": vuln, "json": vuln.serialize()}

def ioc_to_stix(ioc: dict) -> dict | None:
    patterns = {
        "ip":     f"[ipv4-addr:value = '{ioc['value']}']",
        "domain": f"[domain-name:value = '{ioc['value']}']",
        "hash":   f"[file:hashes.SHA-256 = '{ioc['value']}']",
        "url":    f"[url:value = '{ioc['value']}']",
    }
    pattern = patterns.get(ioc.get("type"))
    if not pattern:
        return None
    indicator = Indicator(
        name=f"{ioc['type'].upper()} — {ioc['value'][:50]}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"],
        valid_from=datetime.now(timezone.utc),
        custom_properties={"x_tlp": ioc.get("tlp", "TLP:AMBER")}
    )
    return {"stix_id": indicator.id, "object": indicator, "json": indicator.serialize()}

def export_bundle(objects: list, output_path: str) -> str:
    bundle = Bundle(objects=objects, allow_custom=True)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(bundle.serialize(pretty=True))
    print(f"[STIX] Bundle exporté : {output_path}")
    return output_path

import os
