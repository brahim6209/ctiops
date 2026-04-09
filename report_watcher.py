"""
CTIOps Report Watcher
Surveille un répertoire de dépôt, détecte les rapports de scan,
les lie automatiquement à un projet/build, et les traite.

Structure attendue :
  /opt/ctiops/reports/
  └── {project}/
      └── {build}/
          ├── trivy-report.json
          ├── gitleaks-report.json
          ├── owasp-report.json
          └── ...

Ou dépôt flat avec metadata dans le nom :
  /opt/ctiops/reports/
  └── {project}__{build}__{tool}.json
"""
import os, json, time, shutil, hashlib, threading
from datetime import datetime
from database import get_conn
from auto_detector import detect_and_parse
from pipeline_processor import process_build

WATCH_DIR    = os.environ.get("CTIOPS_WATCH_DIR", "/opt/ctiops/reports")
DONE_DIR     = os.environ.get("CTIOPS_DONE_DIR",  "/opt/ctiops/processed")
ERROR_DIR    = os.environ.get("CTIOPS_ERROR_DIR", "/opt/ctiops/errors")
POLL_INTERVAL = int(os.environ.get("CTIOPS_POLL", "5"))

# Formats de noms de fichiers reconnus
TOOL_PATTERNS = {
    "trivy":    ["trivy", "trivy-report", "trivy_report"],
    "gitleaks": ["gitleaks", "gitleaks-report", "gitleaks_report", "secrets"],
    "owasp":    ["owasp", "dependency-check", "dependency_check", "owasp-report"],
    "owasp-zap":["zap", "owasp-zap", "zap-report", "zap_report"],
    "semgrep":  ["semgrep", "sast", "gl-sast-report"],
    "snyk":     ["snyk", "snyk-report"],
    "grype":    ["grype", "grype-report"],
    "checkov":  ["checkov", "iac"],
    "sonarqube":["sonar", "sonarqube"],
}

already_processed = set()

def guess_tool(filename: str) -> str:
    """Devine l'outil depuis le nom du fichier."""
    name = filename.lower().replace(".json","").replace(".sarif","")
    for tool, patterns in TOOL_PATTERNS.items():
        if any(p in name for p in patterns):
            return tool
    return "unknown"

def parse_path(filepath: str) -> dict:
    """
    Extrait project/build/tool depuis le chemin.
    
    Supporte :
    1. /opt/ctiops/reports/myproject/build-42/trivy-report.json
    2. /opt/ctiops/reports/myproject__42__trivy.json
    3. /opt/ctiops/reports/trivy-report.json  (project=unknown)
    """
    rel     = os.path.relpath(filepath, WATCH_DIR)
    parts   = rel.replace("\\","/").split("/")
    filename= os.path.basename(filepath)
    name_no_ext = os.path.splitext(filename)[0]

    # Format 2 : project__build__tool.json
    if "__" in name_no_ext:
        segments = name_no_ext.split("__")
        if len(segments) >= 3:
            return {"project": segments[0], "build": segments[1], "tool": segments[2]}
        if len(segments) == 2:
            return {"project": segments[0], "build": segments[1], "tool": guess_tool(filename)}

    # Format 1 : répertoire project/build/fichier
    if len(parts) >= 3:
        return {"project": parts[0], "build": parts[1], "tool": guess_tool(filename)}
    if len(parts) == 2:
        return {"project": parts[0], "build": "0",      "tool": guess_tool(filename)}

    # Format 3 : fichier plat
    return {"project": "unknown", "build": "0", "tool": guess_tool(filename)}


def _auto_enrich_cves(conn, findings):
    """Insère automatiquement les nouvelles CVE dans la table CVE pour enrichissement futur."""
    inserted = 0
    for f in findings:
        cve_id = f.get('id', '') or f.get('cve_id', '')
        if not cve_id or not cve_id.startswith('CVE-'):
            continue
        exists = conn.execute("SELECT id FROM cve WHERE id=?", (cve_id,)).fetchone()
        if not exists:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO cve
                    (id, description, cvss_score, severity, source, attack_type, created_at)
                    VALUES (?,?,?,?,?,?,datetime('now'))
                """, (
                    cve_id,
                    f.get('title', '') or f.get('description', ''),
                    float(f.get('cvss', 0) or 0),
                    f.get('severity', 'UNKNOWN'),
                    'trivy-scan',
                    f.get('category', '') or f.get('vuln_type', '')
                ))
                inserted += 1
            except Exception:
                pass
    if inserted > 0:
        conn.commit()
        print(f"[WATCHER] Auto-inserted {inserted} new CVEs into CVE table")
    return inserted

def file_hash(filepath: str) -> str:
    return hashlib.md5(open(filepath,"rb").read()).hexdigest()

def process_file(filepath: str):
    """Traite un fichier de rapport détecté."""
    meta    = parse_path(filepath)
    project = meta["project"]
    build   = meta["build"]
    tool    = meta["tool"]
    fname   = os.path.basename(filepath)

    print(f"[WATCHER] {fname} → project={project} build=#{build} tool={tool}")

    try:
        # 1. Lire et parser
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            raw = json.load(f)

        # 2. Auto-détection outil si inconnu
        detected = detect_and_parse(raw)
        if tool == "unknown" and detected["detected"]:
            tool = detected["tool"]
            print(f"[WATCHER] Auto-detected tool: {tool}")

        findings = detected["findings"]
        if not findings:
            print(f"[WATCHER] {fname} — 0 findings, skipping ML")
            _move_file(filepath, DONE_DIR, project, build)
            return

        # 3. Pipeline ML complet
        result = process_build(project, build, tool, findings)

        # 3.5 Auto-insert new CVEs
        _auto_enrich_cves(conn, result["findings"])

        # 4. Persister en base
        conn = get_conn()
        inserted = 0
        for f in result["findings"]:
            details = json.dumps({
                "project":       project,
                "build":         build,
                "tool":          tool,
                "package":       f.get("package",""),
                "version":       f.get("version",""),
                "fixed":         f.get("fixed",""),
                "file":          f.get("file",""),
                "cvss":          f.get("cvss",0),
                "reality_score": f.get("reality_score",0),
                "category":      f.get("category",""),
                "attack_path":   f.get("attack_path",""),
                "mitre":         f.get("mitre",""),
                "title":         f.get("title",""),
                "source_file":   fname,
            })
            try:
                conn.execute("""
                    INSERT INTO incident
                    (source, severity, details, created_at)
                    VALUES (?,?,?,datetime('now'))
                """, (tool, f.get("severity","UNKNOWN"), details))
                inserted += 1
            except Exception:
                pass
        conn.commit()

        # 5. Déplacer vers processed
        dest = _move_file(filepath, DONE_DIR, project, build)

        # 6. Sauvegarder metadata du traitement
        meta_file = dest + ".meta.json"
        with open(meta_file, "w") as mf:
            json.dump({
                "processed_at":   datetime.utcnow().isoformat(),
                "source_file":    fname,
                "project":        project,
                "build":          build,
                "tool":           tool,
                "total_findings": result["total"],
                "critical":       result["critical"],
                "high":           result["high"],
                "avg_reality":    result["avg_reality"],
                "categories":     result["categories"],
                "attack_paths":   result["attack_paths"],
                "inserted":       inserted,
            }, mf, indent=2)

        print(f"[WATCHER] ✓ {fname} — {inserted} findings | risk={'CRITICAL' if result['critical']>0 else 'HIGH' if result['high']>0 else 'MEDIUM'} | attack_paths={result['attack_paths']}")

    except json.JSONDecodeError as e:
        print(f"[WATCHER] ✗ {fname} — JSON invalide: {e}")
        _move_file(filepath, ERROR_DIR, project, build)
    except Exception as e:
        print(f"[WATCHER] ✗ {fname} — Erreur: {e}")
        _move_file(filepath, ERROR_DIR, project, build)

def _move_file(filepath: str, dest_base: str, project: str, build: str) -> str:
    """Déplace le fichier vers done/error en préservant la structure."""
    dest_dir = os.path.join(dest_base, project, f"build-{build}")
    ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    name = f"{ts}_{os.path.basename(filepath)}"
    # Essayer plusieurs stratégies
    for dest_dir_try in [
        dest_dir,
        os.path.join(os.path.expanduser("~"), ".ctiops", "processed", project, f"build-{build}")
    ]:
        try:
            os.makedirs(dest_dir_try, exist_ok=True)
            dest = os.path.join(dest_dir_try, name)
            shutil.copy2(filepath, dest)  # copie d'abord
            try:
                os.remove(filepath)  # supprime si possible
            except PermissionError:
                pass  # pas grave si on ne peut pas supprimer
            return dest
        except PermissionError:
            continue
    # Dernier recours — juste copier sans supprimer
    dest = os.path.join("/tmp", name)
    shutil.copy2(filepath, dest)
    return dest

def scan_directory():
    """Scanne le répertoire de watch pour nouveaux fichiers."""
    if not os.path.exists(WATCH_DIR):
        return
    for root, dirs, files in os.walk(WATCH_DIR):
        dirs[:] = [d for d in dirs if d not in ["__pycache__",".git"]]
        for fname in files:
            if not (fname.endswith(".json") or fname.endswith(".sarif")):
                continue
            fpath = os.path.join(root, fname)
            fhash = file_hash(fpath)
            if fhash in already_processed:
                continue
            already_processed.add(fhash)
            process_file(fpath)

def _ensure_dirs(*dirs):
    """Crée les répertoires avec les bonnes permissions, fallback si permission denied."""
    for d in dirs:
        try:
            os.makedirs(d, exist_ok=True)
            os.chmod(d, 0o775)
        except PermissionError:
            # Fallback vers HOME si pas les droits
            alt = os.path.join(os.path.expanduser("~"), ".ctiops", os.path.basename(d))
            os.makedirs(alt, exist_ok=True)
            print(f"[WATCHER] Permission denied sur {d} — fallback vers {alt}")
            return alt
    return None

def _safe_move(src, dest_dir):
    """Déplace un fichier, crée le répertoire si nécessaire avec fallback."""
    try:
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, os.path.basename(src))
        import shutil
        shutil.move(src, dest)
        return dest
    except PermissionError:
        # Fallback vers HOME
        alt_dir = os.path.join(os.path.expanduser("~"), ".ctiops",
                               os.path.relpath(dest_dir, "/opt/ctiops"))
        os.makedirs(alt_dir, exist_ok=True)
        dest = os.path.join(alt_dir, os.path.basename(src))
        import shutil
        shutil.move(src, dest)
        return dest

def watch_loop():
    """Boucle principale du watcher."""
    print(f"[WATCHER] Démarré — surveillance de {WATCH_DIR} (poll={POLL_INTERVAL}s)")
    _ensure_dirs(WATCH_DIR, DONE_DIR, ERROR_DIR)
    while True:
        try:
            scan_directory()
        except Exception as e:
            print(f"[WATCHER] Erreur scan: {e}")
        time.sleep(POLL_INTERVAL)

def start_watcher():
    """Démarre le watcher dans un thread daemon."""
    t = threading.Thread(target=watch_loop, daemon=True, name="report-watcher")
    t.start()
    return t

if __name__ == "__main__":
    watch_loop()
