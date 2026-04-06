"""
api.py — CTI Platform REST API v2.0
100% dynamique — NVD + VirusTotal + MISP + LeakCheck
"""
import os, json, datetime, threading
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
CORS(app, origins=["http://localhost:4200"])


# ══════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════
@app.route("/api/health")
def health():
    from database import get_conn
    try:
        with get_conn() as c:
            cve = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            inc = c.execute("SELECT COUNT(*) FROM incident").fetchone()[0]
            ioc = c.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
        db = "ok"
    except Exception as e:
        cve = inc = ioc = 0
        db = str(e)
    return jsonify({
        "status":    "ok",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "version":   "2.0",
        "database":  db,
        "counts":    {"cve": cve, "incidents": inc, "ioc": ioc},
        "services":  {
            "nvd":        bool(os.getenv("NVD_API_KEY")),
            "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "misp":       bool(os.getenv("MISP_URL")),
            "leakcheck":  bool(os.getenv("LEAKCHECK_API_KEY")),
        }
    })

# ══════════════════════════════════════════════════════════════════
# MODULE 1: CLOUD VULNERABILITIES
# ══════════════════════════════════════════════════════════════════
@app.route("/api/v1/stats")
def api_stats():
    from database import get_conn
    with get_conn() as c:
        total_cve    = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        critical_cve = c.execute("SELECT COUNT(*) FROM cve WHERE cvss_score >= 9.0").fetchone()[0]
        high_cve     = c.execute("SELECT COUNT(*) FROM cve WHERE cvss_score >= 7.0 AND cvss_score < 9.0").fetchone()[0]
        exploit_cve  = c.execute("SELECT COUNT(*) FROM cve WHERE has_exploit=1").fetchone()[0]
        active_cve   = c.execute("SELECT COUNT(*) FROM cve WHERE actively_exploited=1").fetchone()[0]
        total_inc    = c.execute("SELECT COUNT(*) FROM incident").fetchone()[0]
        critical_inc = c.execute("SELECT COUNT(*) FROM incident WHERE severity='CRITICAL'").fetchone()[0]
        total_ioc    = c.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
        sev_rows     = c.execute("SELECT severity, COUNT(*) as n FROM cve GROUP BY severity").fetchall()
        inc_rows     = c.execute("SELECT event_type, COUNT(*) as n FROM incident GROUP BY event_type ORDER BY n DESC").fetchall()
        src_rows     = c.execute("SELECT source, COUNT(*) as n FROM cve GROUP BY source ORDER BY n DESC").fetchall()

    risk_score = min(100, critical_cve*15 + high_cve*8 + critical_inc*10 + exploit_cve*5)
    return jsonify({
        "cve": {
            "total":         total_cve,
            "critical":      critical_cve,
            "high":          high_cve,
            "with_exploit":  exploit_cve,
            "active_exploit":active_cve,
            "distribution":  {r["severity"]: r["n"] for r in sev_rows},
            "by_source":     {r["source"]: r["n"] for r in src_rows if r["source"]},
        },
        "incidents": {
            "total":        total_inc,
            "critical":     critical_inc,
            "distribution": {r["event_type"]: r["n"] for r in inc_rows},
        },
        "ioc":  {"total": total_ioc},
        "risk": {
            "score": risk_score,
            "level": "CRITICAL" if risk_score>=80 else "HIGH" if risk_score>=60 else "MEDIUM" if risk_score>=30 else "LOW"
        },
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

@app.route("/api/v1/cve")
def api_cve():
    from database import get_conn
    severity = request.args.get("severity", "")
    q        = request.args.get("q", "").lower()
    min_cvss = float(request.args.get("min_cvss", 0))
    exploit  = request.args.get("exploit", "")
    limit    = int(request.args.get("limit", 200))
    offset   = int(request.args.get("offset", 0))

    sql = "SELECT * FROM cve WHERE 1=1"
    params = []
    if severity:
        sql += " AND severity=?"; params.append(severity)
    if min_cvss:
        sql += " AND cvss_score>=?"; params.append(min_cvss)
    attack_type = request.args.get("attack_type", "")
    if attack_type:
        sql += " AND attack_type=?"; params.append(attack_type)

    if exploit == "true":
        sql += " AND (has_exploit=1 OR actively_exploited=1)"
    if q:
        sql += " AND (LOWER(id) LIKE ? OR LOWER(description) LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]
    sql += " ORDER BY cvss_score DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    # Count total sans LIMIT/OFFSET
    count_sql = sql.replace("SELECT *", "SELECT COUNT(*)").split("ORDER BY")[0]
    count_params = params[:-2]  # enlever limit et offset
    with get_conn() as c:
        total = c.execute(count_sql, count_params).fetchone()[0]
        rows  = c.execute(sql, params).fetchall()
    return jsonify({"data": [dict(r) for r in rows], "total": total})

@app.route("/api/v1/cve/<cve_id>")
def api_cve_detail(cve_id):
    from database import get_conn
    with get_conn() as c:
        row = c.execute("SELECT * FROM cve WHERE id=?", [cve_id]).fetchone()
    if not row:
        return jsonify({"error": "CVE not found"}), 404
    return jsonify(dict(row))

@app.route("/api/v1/cve/collect", methods=["POST"])
def api_collect_cve():
    def do_collect():
        from nvd_collector import run_collector
        days = request.json.get("days", 7) if request.json else 7
        run_collector(days_back=days)
    threading.Thread(target=do_collect, daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/api/v1/cve/exploit-stats")
def api_exploit_stats():
    from database import get_conn
    with get_conn() as c:
        total        = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        has_exploit  = c.execute("SELECT COUNT(*) FROM cve WHERE has_exploit=1").fetchone()[0]
        active       = c.execute("SELECT COUNT(*) FROM cve WHERE actively_exploited=1").fetchone()[0]
        high_epss    = c.execute("SELECT COUNT(*) FROM cve WHERE epss_score>0.5").fetchone()[0]
        top = c.execute("""
            SELECT id, cvss_score, severity, epss_score,
                   actively_exploited, exploit_source, description
            FROM cve
            WHERE has_exploit=1 OR actively_exploited=1 OR epss_score>0.3
            ORDER BY actively_exploited DESC, epss_score DESC, cvss_score DESC
            LIMIT 20
        """).fetchall()
    return jsonify({
        "summary": {
            "total_cve":           total,
            "with_public_exploit": has_exploit,
            "actively_exploited":  active,
            "high_epss":           high_epss,
            "exploit_rate":        round(has_exploit/total*100,1) if total else 0,
        },
        "top_exploited": [dict(r) for r in top]
    })

@app.route("/api/v1/cve/enrich-exploits", methods=["POST"])
def api_enrich_exploits():
    def do_enrich():
        from nvd_collector import update_exploit_status_in_db
        update_exploit_status_in_db()
    threading.Thread(target=do_enrich, daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/api/v1/cve/<cve_id>/validate")
def api_validate_cve(cve_id):
    try:
        from cve_validator import validate_cve
        return jsonify(validate_cve(cve_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/cve/<cve_id>/relevance", methods=["POST"])
def api_cve_relevance(cve_id):
    try:
        from cve_validator import check_relevance
        data = request.get_json()
        components = data.get("components", []) if data else []
        return jsonify(check_relevance(cve_id, components))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/cve/<cve_id>/priority")
def api_cve_priority(cve_id):
    try:
        from cve_validator import calculate_priority_score
        return jsonify(calculate_priority_score(cve_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── IOC ───────────────────────────────────────────────────────────
@app.route("/api/v1/ioc")
def api_ioc():
    from database import get_conn
    ioc_type  = request.args.get("type", "")
    min_score = float(request.args.get("min_score", 0))
    limit     = int(request.args.get("limit", 100))
    with get_conn() as c:
        rows = c.execute("""
            SELECT i.*, e.score FROM ioc i
            LEFT JOIN enrichment e ON i.value=e.ioc_value
            ORDER BY e.score DESC NULLS LAST LIMIT ?
        """, [limit]).fetchall()
    result = [dict(r) for r in rows
              if (not ioc_type or r["type"]==ioc_type)
              and float(r["score"] or 0) >= min_score]
    return jsonify({"data": result, "total": len(result)})

@app.route("/api/v1/ioc/enrich", methods=["POST"])
def api_enrich_ioc():
    try:
        from virustotal import enrich_ioc
        data = request.get_json()
        return jsonify(enrich_ioc(data.get("value"), data.get("type","ip")))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── INCIDENTS ─────────────────────────────────────────────────────
@app.route("/api/v1/incidents")
def api_incidents():
    from database import get_conn
    severity = request.args.get("severity", "")
    source   = request.args.get("source", "")
    limit    = int(request.args.get("limit", 100))
    sql = "SELECT * FROM incident WHERE 1=1"
    params = []
    if severity:
        sql += " AND severity=?"; params.append(severity)
    if source:
        sql += " AND source=?"; params.append(source)
    sql += " ORDER BY created_at DESC LIMIT ?"; params.append(limit)
    # Count total sans LIMIT/OFFSET
    count_sql = sql.replace("SELECT *", "SELECT COUNT(*)").split("ORDER BY")[0]
    count_params = params[:-1]  # enlever seulement limit
    with get_conn() as c:
        total = c.execute(count_sql, count_params).fetchone()[0]
        rows  = c.execute(sql, params).fetchall()
    return jsonify({"data": [dict(r) for r in rows], "total": total})

# ── MISP ──────────────────────────────────────────────────────────
@app.route("/api/v1/misp/feed")
def api_misp_feed():
    try:
        from misp_feed import get_misp_intelligence
        return jsonify(get_misp_intelligence())
    except Exception as e:
        return jsonify({"error": str(e), "status": "misp_unavailable"}), 503

@app.route("/api/v1/misp/push", methods=["POST"])
def api_misp_push():
    try:
        from misp_connector import push_event
        return jsonify(push_event(request.get_json()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════
# MODULE 2: DEVSECOPS PIPELINE
# ══════════════════════════════════════════════════════════════════
@app.route("/api/v1/devsecops/report", methods=["POST"])
def api_devsecops_report():
    try:
        from devsecops_collector import process_report
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON body"}), 400
        return jsonify(process_report(
            data.get("tool", "unknown"),
            data.get("project", "unknown"),
            data.get("report", {}),
            data.get("metadata", {})
        ))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/devsecops/history")
def api_devsecops_history():
    from database import get_conn
    project = request.args.get("project", "")
    tool    = request.args.get("tool", "")
    limit   = int(request.args.get("limit", 50))
    sql = "SELECT * FROM incident WHERE source IN ('gitleaks','owasp','trivy','sonarqube','custom')"
    params = []
    if project:
        sql += " AND repo LIKE ?"; params.append(f"%{project}%")
    if tool:
        sql += " AND source=?"; params.append(tool)
    sql += " ORDER BY created_at DESC LIMIT ?"; params.append(limit)
    # Count total sans LIMIT/OFFSET
    count_sql = sql.replace("SELECT *", "SELECT COUNT(*)").split("ORDER BY")[0]
    count_params = params[:-1]  # enlever seulement limit
    with get_conn() as c:
        total = c.execute(count_sql, count_params).fetchone()[0]
        rows  = c.execute(sql, params).fetchall()
    return jsonify({"data": [dict(r) for r in rows], "total": total})

@app.route("/api/v1/devsecops/projects")
def api_devsecops_projects():
    from database import get_conn
    with get_conn() as c:
        rows = c.execute("""
            SELECT repo as project, COUNT(*) as total_scans,
                   SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high,
                   MAX(created_at) as last_scan,
                   GROUP_CONCAT(DISTINCT source) as tools
            FROM incident
            WHERE source IN ('gitleaks','owasp','trivy','sonarqube','custom')
            GROUP BY repo ORDER BY critical DESC
        """).fetchall()
    return jsonify({"data": [dict(r) for r in rows]})

@app.route("/api/v1/devsecops/scanners")
def api_scanners():
    return jsonify({"scanners": [
        {"id": "gitleaks",  "name": "GitLeaks",              "type": "secrets"},
        {"id": "trivy",     "name": "Trivy",                 "type": "cve"},
        {"id": "owasp",     "name": "OWASP Dependency Check","type": "cve"},
        {"id": "sonarqube", "name": "SonarQube",             "type": "code_quality"},
        {"id": "semgrep",   "name": "Semgrep",               "type": "sast"},
        {"id": "snyk",      "name": "Snyk",                  "type": "cve"},
        {"id": "custom",    "name": "Custom Scanner",        "type": "any"},
    ]})

# ── ZERODAY MONITOR ───────────────────────────────────────────────
@app.route("/api/v1/threat-intel/zeroday", methods=["POST"])
def api_zeroday_monitor():
    try:
        from threat_intel import monitor_zerodays_for_components
        data = request.get_json()
        components = data.get("components", []) if data else []
        if not components:
            return jsonify({"error": "components list required"}), 400
        alerts = monitor_zerodays_for_components(components)
        return jsonify({
            "components_checked": len(components),
            "alerts_found":       len(alerts),
            "critical_alerts":    sum(1 for a in alerts if a["alert_level"]=="CRITICAL"),
            "alerts":             alerts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/threat-intel/feeds")
def api_threat_feeds():
    from database import get_conn
    source = request.args.get("source", "")
    limit  = int(request.args.get("limit", 100))
    with get_conn() as c:
        if source:
            rows = c.execute("SELECT * FROM ioc WHERE source=? ORDER BY created_at DESC LIMIT ?", [source, limit]).fetchall()
        else:
            rows = c.execute("SELECT * FROM ioc ORDER BY created_at DESC LIMIT ?", [limit]).fetchall()
        stats = c.execute("SELECT source, COUNT(*) as n FROM ioc GROUP BY source ORDER BY n DESC").fetchall()
    return jsonify({
        "data":    [dict(r) for r in rows],
        "total":   len(rows),
        "sources": {r["source"]: r["n"] for r in stats},
    })

@app.route("/api/v1/threat-intel/collect", methods=["POST"])
def api_collect_threat_intel():
    def do_collect():
        from threat_intel import run_threat_intel_collector
        days = request.json.get("days", 7) if request.json else 7
        run_threat_intel_collector(days=days)
    threading.Thread(target=do_collect, daemon=True).start()
    return jsonify({"status": "started"})

# ══════════════════════════════════════════════════════════════════
# MODULE 3: ML & ATTACK PREDICTION
# ══════════════════════════════════════════════════════════════════
@app.route("/api/v1/ml/kill-chain")
def api_kill_chain():
    try:
        from attack_engine import analyze_kill_chain
        return jsonify(analyze_kill_chain())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/ml/attack-graph")
def api_attack_graph():
    try:
        from attack_engine import build_relation_graph
        return jsonify(build_relation_graph())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/ml/attack-paths")
def api_attack_paths():
    try:
        from attack_engine import predict_attack_paths
        return jsonify(predict_attack_paths())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/ml/risk-score")
def api_risk_score():
    try:
        from attack_engine import calculate_risk_scores
        return jsonify(calculate_risk_scores())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════
# MODULE 4: BREACH CHECK (LeakCheck + HIBP k-anonymity)
# ══════════════════════════════════════════════════════════════════
@app.route("/api/v1/breach/email", methods=["POST"])
def api_breach_email():
    try:
        from threat_intel import check_email_leakcheck
        data = request.get_json()
        email = data.get("email", "")
        if not email or "@" not in email:
            return jsonify({"error": "Email invalide"}), 400
        return jsonify(check_email_leakcheck(email))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/breach/domain", methods=["POST"])
def api_breach_domain():
    try:
        from threat_intel import check_domain_leakcheck
        data = request.get_json()
        domain = data.get("domain", "")
        if not domain:
            return jsonify({"error": "Domain requis"}), 400
        return jsonify(check_domain_leakcheck(domain))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/breach/username", methods=["POST"])
def api_breach_username():
    try:
        from threat_intel import check_username_leakcheck
        data = request.get_json()
        username = data.get("username", "")
        if not username:
            return jsonify({"error": "Username requis"}), 400
        return jsonify(check_username_leakcheck(username))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/breach/password", methods=["POST"])
def api_breach_password():
    try:
        from threat_intel import check_password_breach
        data = request.get_json()
        password = data.get("password", "")
        if not password:
            return jsonify({"error": "Password requis"}), 400
        return jsonify(check_password_breach(password))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/breach/bulk", methods=["POST"])
def api_breach_bulk():
    try:
        from threat_intel import check_email_leakcheck, check_domain_leakcheck
        import time as _time
        data      = request.get_json()
        emails    = data.get("emails", [])[:10]
        domain    = data.get("domain", "")
        results   = {"emails": [], "domain": {}}
        for email in emails:
            results["emails"].append(check_email_leakcheck(email))
            _time.sleep(0.5)
        if domain:
            results["domain"] = check_domain_leakcheck(domain)
        compromised = sum(1 for e in results["emails"] if e.get("breached"))
        results["summary"] = {
            "total_checked":      len(emails),
            "compromised_emails": compromised,
            "risk_level":         "CRITICAL" if compromised > 0 else "LOW"
        }
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════
# MODULE 5: EXPORT
# ══════════════════════════════════════════════════════════════════
@app.route("/api/v1/export/json/<section>")
def export_json(section):
    import json as json_lib
    from database import get_conn
    data = []
    with get_conn() as c:
        if section == "cve":
            data = [dict(r) for r in c.execute("SELECT * FROM cve ORDER BY cvss_score DESC").fetchall()]
        elif section == "incidents":
            data = [dict(r) for r in c.execute("SELECT * FROM incident ORDER BY created_at DESC").fetchall()]
        elif section == "ioc":
            data = [dict(r) for r in c.execute("SELECT i.*, e.score FROM ioc i LEFT JOIN enrichment e ON i.value=e.ioc_value").fetchall()]
    export = {
        "generated":      datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform":       "CTI Cloud-Native v2.0",
        "classification": "TLP:AMBER",
        "section":        section,
        "count":          len(data),
        "data":           data
    }
    resp = Response(json_lib.dumps(export, indent=2, default=str), mimetype="application/json")
    resp.headers["Content-Disposition"] = f"attachment; filename=CTI_{section}_{datetime.date.today().strftime('%Y%m%d')}.json"
    return resp

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

@app.route('/api/v1/ml/model', methods=['GET'])
def ml_model_info():
    try:
        from ml_engine import get_model_info
        return jsonify(get_model_info())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/ml/train', methods=['POST'])
def ml_train():
    try:
        from ml_engine import train_model
        model = train_model()
        return jsonify({
            'status': 'trained',
            'auc_roc': round(model.get('auc_roc', 0), 3),
            'trained_on': model.get('n_train', 0),
            'n_positive': model.get('n_positive', 0),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Cloud + IOC endpoints
# Enregistrer les endpoints cloud/IOC
from api_cloud_endpoints import register_cloud_endpoints
register_cloud_endpoints(app)

from devsecops_cve_api import register_devsecops_cve_routes
register_devsecops_cve_routes(app)

if __name__ == "__main__":
    # Démarrer le scheduler automatique
    try:
        from auto_scheduler import start_scheduler_thread
        start_scheduler_thread()
        print("[CTI] Auto-scheduler démarré")
    except Exception as e:
        print(f"[CTI] Scheduler error: {e}")

    from database import init_db
    import schedule, time as _time

    init_db()

    def collect_on_start():
        try:
            from nvd_collector import run_collector
            print("[AUTO] Collecte NVD au démarrage...")
            run_collector(days_back=7)
            from nvd_collector import update_exploit_status_in_db
            update_exploit_status_in_db()
            print("[AUTO] Collecte terminée")
            # Auto-sync MISP
            try:
                from misp_connector import push_cves, push_incidents
                push_cves(limit=10)
                push_incidents(limit=20)
                print("[AUTO] MISP sync OK")
            except Exception as me:
                print(f"[AUTO] MISP sync: {me}")
            # Auto-sync MISP
            try:
                from misp_connector import push_cves, push_incidents
                push_cves(limit=10)
                push_incidents(limit=20)
                print("[AUTO] MISP sync OK")
            except Exception as me:
                print(f"[AUTO] MISP sync: {me}")
        except Exception as e:
            print(f"[AUTO] Erreur: {e}")

    def scheduler_loop():
        schedule.every(1).hours.do(collect_on_start)
        while True:
            schedule.run_pending()
            _time.sleep(60)

    threading.Thread(target=collect_on_start, daemon=True).start()
    threading.Thread(target=scheduler_loop, daemon=True).start()

    print("="*50)
    print("CTI Platform API v2.0")
    print("="*50)
    print("Backend:  http://0.0.0.0:5000")
    print("Frontend: http://localhost:4200")
    print("Health:   http://localhost:5000/api/health")
    print("="*50)
    app.run(host="0.0.0.0", port=5000, debug=False)

# ── SECRET CHECKER ────────────────────────────────────────────────
@app.route("/api/v1/breach/secrets/scan", methods=["POST"])
def api_scan_secrets():
    """Scan automatique des secrets GitLeaks par type."""
    try:
        from secret_checker import check_secret
        from database import get_conn
        
        data = request.get_json() or {}
        build = data.get("build", "")
        
        with get_conn() as c:
            sql = """SELECT id, details FROM incident 
                     WHERE source='gitleaks'"""
            params = []
            if build:
                sql += " AND json_extract(details,'$.build')=?"
                params.append(str(build))
            rows = c.execute(sql, params).fetchall()
        
        results = []
        for row in rows:
            try:
                det = json.loads(row["details"] or "{}")
                rule_id = det.get("rule_id", "generic-api-key")
                secret_hint = det.get("secret_hint", "")
                # Construire le contexte depuis le fichier et la ligne
                context = f"{det.get('file','')} line:{det.get('line','')} {rule_id}"
                
                result = check_secret(rule_id, secret_hint, context)
                result["incident_id"] = row["id"]
                result["build"] = det.get("build")
                result["file"] = det.get("file", "")
                result["hint"] = secret_hint
                results.append(result)
            except Exception as e:
                results.append({"incident_id": row["id"], "error": str(e)})
        
        # Stats
        checked = [r for r in results if r.get("checked")]
        compromised = [r for r in checked if r.get("pwned") or r.get("found")]
        
        return jsonify({
            "total": len(results),
            "checked": len(checked),
            "compromised": len(compromised),
            "safe": len(checked) - len(compromised),
            "results": results
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
