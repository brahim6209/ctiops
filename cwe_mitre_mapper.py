import os
import json

"""
cwe_mitre_mapper.py — Mapping officiel CWE → Attack Type → MITRE ATT&CK
Sources :
  - MITRE CWE → ATT&CK mapping (https://cwe.mitre.org)
  - NIST NVD CWE list
  - ATT&CK Enterprise v14
"""

# ── CWE → Attack Type ────────────────────────────────────────────
# Source : MITRE CWE taxonomy + NVD enrichment
CWE_TO_ATTACK_TYPE = {
    # RCE — Remote Code Execution
    "CWE-78":   "RCE",   # OS Command Injection
    "CWE-94":   "RCE",   # Code Injection
    "CWE-95":   "RCE",   # Eval Injection
    "CWE-96":   "RCE",   # Static Code Injection
    "CWE-434":  "RCE",   # Unrestricted File Upload
    "CWE-502":  "RCE",   # Deserialization of Untrusted Data
    "CWE-77":   "RCE",   # Command Injection (generic)
    "CWE-917":  "RCE",   # Expression Language Injection
    "CWE-1321": "RCE",   # Prototype Pollution → RCE

    # SQLI — SQL Injection
    "CWE-89":   "SQLI",  # SQL Injection
    "CWE-564":  "SQLI",  # SQL Injection — Hibernate
    "CWE-943":  "SQLI",  # NoSQL Injection

    # XSS — Cross Site Scripting
    "CWE-79":   "XSS",   # XSS (Reflected/Stored/DOM)
    "CWE-80":   "XSS",   # Basic XSS
    "CWE-81":   "XSS",   # Improper Sanitization of Script

    # SSRF — Server Side Request Forgery
    "CWE-918":  "SSRF",  # SSRF

    # AUTH_BYPASS — Authentication/Authorization
    "CWE-287":  "AUTH_BYPASS",  # Improper Authentication
    "CWE-306":  "AUTH_BYPASS",  # Missing Authentication
    "CWE-384":  "AUTH_BYPASS",  # Session Fixation
    "CWE-798":  "AUTH_BYPASS",  # Hardcoded Credentials
    "CWE-862":  "AUTH_BYPASS",  # Missing Authorization
    "CWE-863":  "AUTH_BYPASS",  # Incorrect Authorization
    "CWE-285":  "AUTH_BYPASS",  # Improper Authorization
    "CWE-295":  "AUTH_BYPASS",  # Improper Certificate Validation
    "CWE-732":  "AUTH_BYPASS",  # Incorrect Permission Assignment
    "CWE-1188": "AUTH_BYPASS",  # Insecure Default Initialization of Resource
    "CWE-1391": "AUTH_BYPASS",  # Use of Weak Credentials
    "CWE-1392": "AUTH_BYPASS",  # Use of Default Credentials
    "CWE-1393": "AUTH_BYPASS",  # Use of Default Password
    "CWE-1390": "AUTH_BYPASS",  # Weak Authentication

    # PRIVESC — Privilege Escalation
    "CWE-269":  "PRIVESC",  # Improper Privilege Management
    "CWE-250":  "PRIVESC",  # Execution with Unnecessary Privileges
    "CWE-648":  "PRIVESC",  # Incorrect Use of Privileged APIs
    "CWE-266":  "PRIVESC",  # Incorrect Privilege Assignment

    # PATH_TRAVERSAL
    "CWE-22":   "PATH_TRAVERSAL",  # Path Traversal
    "CWE-23":   "PATH_TRAVERSAL",  # Relative Path Traversal
    "CWE-24":   "PATH_TRAVERSAL",  # .. Path Traversal
    "CWE-36":   "PATH_TRAVERSAL",  # Absolute Path Traversal

    # XXE — XML External Entity
    "CWE-611":  "XXE",   # XML External Entity Reference
    "CWE-776":  "XXE",   # Billion Laughs / XML DoS

    # SSRF / IDOR
    "CWE-639":  "IDOR",  # Authorization Bypass Through User-Controlled Key
    "CWE-566":  "IDOR",  # Authorization Bypass Through SQL Primary Key

    # DOS — Denial of Service
    "CWE-400":  "DOS",   # Uncontrolled Resource Consumption
    "CWE-770":  "DOS",   # Allocation of Resources Without Limits
    "CWE-674":  "DOS",   # Uncontrolled Recursion
    "CWE-834":  "DOS",   # Excessive Iteration
    "CWE-190":  "DOS",   # Integer Overflow → crash

    # INFO_DISCLOSURE
    "CWE-200":  "INFO_DISCLOSURE",  # Exposure of Sensitive Info
    "CWE-201":  "INFO_DISCLOSURE",  # Insertion of Sensitive Info in Output
    "CWE-209":  "INFO_DISCLOSURE",  # Error Message Contains Sensitive Info
    "CWE-312":  "INFO_DISCLOSURE",  # Cleartext Storage of Sensitive Info
    "CWE-319":  "INFO_DISCLOSURE",  # Cleartext Transmission
    "CWE-359":  "INFO_DISCLOSURE",  # Exposure of Private Info

    # SUPPLY_CHAIN
    "CWE-1104": "SUPPLY_CHAIN",  # Use of Unmaintained Third Party Components
    "CWE-829":  "SUPPLY_CHAIN",  # Inclusion of Functionality from Untrusted Source
    "CWE-494":  "SUPPLY_CHAIN",  # Download of Code Without Integrity Check

    # CONTAINER_ESCAPE
    "CWE-269":  "CONTAINER_ESCAPE",  # Improper Privilege Management (containers)

    # CWE génériques manquants
    "CWE-74":   "RCE",          # Injection (generic)
    "CWE-255":  "AUTH_BYPASS",  # Credentials Management Errors
    "CWE-284":  "AUTH_BYPASS",  # Improper Access Control
    "CWE-347":  "AUTH_BYPASS",  # Improper Verification of Cryptographic Signature
    "CWE-276":  "AUTH_BYPASS",  # Incorrect Default Permissions
    "CWE-352":  "AUTH_BYPASS",  # CSRF
    "CWE-426":  "PRIVESC",      # Untrusted Search Path
    "CWE-427":  "PRIVESC",      # Uncontrolled Search Path Element
    "CWE-noinfo": None,         # No info available
    "NVD-CWE-noinfo": None,     # NVD no info
    "NVD-CWE-Other": None,      # NVD other

    # CLOUD_SPECIFIC
    "CWE-522":  "INFO_DISCLOSURE",  # Insufficiently Protected Credentials
    "CWE-916":  "AUTH_BYPASS",      # Use of Password Hash With Insufficient Effort
}

# ── Attack Type → MITRE ATT&CK (corrigé) ─────────────────────────
# Source : MITRE ATT&CK Enterprise v14
# https://attack.mitre.org
ATTACK_TYPE_TO_MITRE = {
    "RCE": {
        "technique": "T1190",
        "name":      "Exploit Public-Facing Application",
        "tactic":    "Initial Access",
        "url":       "https://attack.mitre.org/techniques/T1190"
    },
    "SQLI": {
        "technique": "T1190",
        "name":      "Exploit Public-Facing Application",
        "tactic":    "Initial Access",
        "url":       "https://attack.mitre.org/techniques/T1190"
    },
    "XSS": {
        "technique": "T1059.007",
        "name":      "JavaScript — Cross-Site Scripting",
        "tactic":    "Execution",
        "url":       "https://attack.mitre.org/techniques/T1059/007"
    },
    "SSRF": {
        "technique": "T1090.002",
        "name":      "External Proxy — SSRF",
        "tactic":    "Command and Control",
        "url":       "https://attack.mitre.org/techniques/T1090/002"
    },
    "AUTH_BYPASS": {
        "technique": "T1078",
        "name":      "Valid Accounts",
        "tactic":    "Defense Evasion / Persistence",
        "url":       "https://attack.mitre.org/techniques/T1078"
    },
    "PRIVESC": {
        "technique": "T1068",
        "name":      "Exploitation for Privilege Escalation",
        "tactic":    "Privilege Escalation",
        "url":       "https://attack.mitre.org/techniques/T1068"
    },
    "PATH_TRAVERSAL": {
        "technique": "T1083",
        "name":      "File and Directory Discovery",
        "tactic":    "Discovery",
        "url":       "https://attack.mitre.org/techniques/T1083"
    },
    "XXE": {
        "technique": "T1059",
        "name":      "Command and Scripting Interpreter",
        "tactic":    "Execution",
        "url":       "https://attack.mitre.org/techniques/T1059"
    },
    "CONTAINER_ESCAPE": {
        "technique": "T1611",
        "name":      "Escape to Host",
        "tactic":    "Privilege Escalation",
        "url":       "https://attack.mitre.org/techniques/T1611"
    },
    "SUPPLY_CHAIN": {
        "technique": "T1195",
        "name":      "Supply Chain Compromise",
        "tactic":    "Initial Access",
        "url":       "https://attack.mitre.org/techniques/T1195"
    },
    "IDOR": {
        "technique": "T1548",
        "name":      "Abuse Elevation Control Mechanism",
        "tactic":    "Privilege Escalation",
        "url":       "https://attack.mitre.org/techniques/T1548"
    },
    "DOS": {
        "technique": "T1499",
        "name":      "Endpoint Denial of Service",
        "tactic":    "Impact",
        "url":       "https://attack.mitre.org/techniques/T1499"
    },
    "INFO_DISCLOSURE": {
        "technique": "T1552",
        "name":      "Unsecured Credentials",
        "tactic":    "Credential Access",
        "url":       "https://attack.mitre.org/techniques/T1552"
    },
    "CLOUD_SPECIFIC": {
        "technique": "T1078.004",
        "name":      "Cloud Accounts",
        "tactic":    "Defense Evasion",
        "url":       "https://attack.mitre.org/techniques/T1078/004"
    },
    "UNKNOWN": {
        "technique": "T1190",
        "name":      "Exploit Public-Facing Application",
        "tactic":    "Initial Access",
        "url":       "https://attack.mitre.org/techniques/T1190"
    },
}

def load_mitre_technique(technique_id: str) -> dict:
    """
    Charger les détails d un technique ATT&CK depuis le fichier STIX officiel.
    Source : MITRE enterprise-attack.json (835 techniques)
    """
    stix_path = os.path.join(os.path.dirname(__file__), "data", "mitre_techniques.json")
    if not os.path.exists(stix_path):
        return ATTACK_TYPE_TO_MITRE.get("UNKNOWN")
    
    try:
        with open(stix_path) as f:
            techniques = json.load(f)
        t = techniques.get(technique_id)
        if t:
            return {
                "technique": technique_id,
                "name":      t["name"],
                "tactic":    ", ".join(t["tactics"]),
                "url":       f"https://attack.mitre.org/techniques/{technique_id.replace('.','/')}"
            }
    except:
        pass
    return ATTACK_TYPE_TO_MITRE.get("UNKNOWN")

def get_mitre_from_attack_type_stix(attack_type: str) -> dict:
    """
    Retourne le mapping MITRE ATT&CK depuis le fichier STIX officiel.
    Fallback sur le dictionnaire statique si STIX non disponible.
    """
    static = ATTACK_TYPE_TO_MITRE.get(attack_type, ATTACK_TYPE_TO_MITRE["UNKNOWN"])
    tech_id = static.get("technique", "T1190")
    
    # Essayer de charger depuis STIX
    stix_data = load_mitre_technique(tech_id)
    if stix_data and stix_data.get("name"):
        return stix_data
    return static

def get_attack_type_from_cwe(cwe_id: str) -> str:
    """
    Retourne le type d'attaque depuis un CWE ID.
    Source officielle NVD/MITRE.
    ex: "CWE-89" → "SQLI"
    """
    if not cwe_id:
        return None
    # Normaliser : "CWE-89", "89", "cwe-89" → "CWE-89"
    cwe_id = cwe_id.upper().strip()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    return CWE_TO_ATTACK_TYPE.get(cwe_id, None)

def get_mitre_from_attack_type(attack_type: str) -> dict:
    """Retourne le mapping MITRE ATT&CK — source STIX officielle avec fallback statique."""
    return get_mitre_from_attack_type_stix(attack_type)

def classify_with_cwe_priority(cwe_id: str, description: str, nlp_classifier=None) -> dict:
    """
    Classification avec priorité :
    1. CWE officiel NVD (si disponible)
    2. NLP TF-IDF (fallback)
    3. Regex patterns (fallback final)
    
    Retourne attack_type + source utilisée
    """
    # 1. CWE officiel
    if cwe_id:
        attack_type = get_attack_type_from_cwe(cwe_id)
        if attack_type:
            return {
                "attack_type": attack_type,
                "source":      "CWE_OFFICIAL",
                "cwe_id":      cwe_id,
                "confidence":  1.0
            }

    # 2. NLP TF-IDF
    if nlp_classifier and nlp_classifier.is_ready:
        result = nlp_classifier.classify_with_confidence(description)
        if result["attack_type"] != "UNKNOWN" and result.get("confidence", 0) >= 0.30:
            return {
                "attack_type": result["attack_type"],
                "source":      "NLP_TFIDF",
                "cwe_id":      cwe_id or "",
                "confidence":  result.get("confidence", 0)
            }

    # 3. Regex fallback
    return {
        "attack_type": "UNKNOWN",
        "source":      "REGEX_FALLBACK",
        "cwe_id":      cwe_id or "",
        "confidence":  0.0
    }

if __name__ == "__main__":
    # Test
    tests = [
        ("CWE-89",  "SQL injection in login form"),
        ("CWE-78",  "OS command injection via user input"),
        ("CWE-918", "SSRF allows access to internal metadata"),
        ("CWE-79",  "XSS via unsanitized input"),
        ("CWE-287", "Authentication bypass via JWT"),
        (None,      "Remote code execution in Apache Tomcat"),
    ]
    print("=== Test CWE → Attack Type → MITRE ===\n")
    for cwe, desc in tests:
        result = classify_with_cwe_priority(cwe, desc)
        mitre  = get_mitre_from_attack_type(result["attack_type"])
        print(f"CWE: {str(cwe):<12} → {result['attack_type']:<20} [{result['source']}]")
        print(f"  MITRE: {mitre['technique']} — {mitre['name']} ({mitre['tactic']})")
