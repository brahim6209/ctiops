"""
api_cloud_endpoints.py — Endpoints Cloud CVE + IOC
À importer dans api.py
"""
from flask import request, jsonify
from database import get_conn
import json


def register_cloud_endpoints(app):
    """Enregistrer tous les endpoints cloud dans l'app Flask."""

    # ── CVE ENRICHMENT 

    @app.route("/api/v1/cve/attack-types")
    def cloud_attack_types():
        try:
            from cve_enricher import get_attack_type_stats
            return jsonify(get_attack_type_stats())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/v1/cve/<cve_id>/detail")
    def cloud_cve_detail(cve_id):
        try:
            from cve_enricher import get_cve_detail
            return jsonify(get_cve_detail(cve_id))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/v1/cve/enrich", methods=["POST"])
    def cloud_enrich_cves():
        import threading
        def do_enrich():
            from cve_enricher import enrich_all_cves
            enrich_all_cves(limit=200, use_vt=False)
        threading.Thread(target=do_enrich, daemon=True).start()
        return jsonify({"status": "started"})

    @app.route("/api/v1/cve/posture")
    def cloud_posture():
        """Recommandations posture sécurité cloud."""
        try:
            with get_conn() as c:
                # Top CVE P0 — actives KEV ou CVSS>=9 avec exploit
                top_cves = c.execute("""
                    SELECT id, severity, cvss_score, epss_score,
                           attack_type, mitre_technique,
                           reality_score, reality_level, description,
                           actively_exploited, has_exploit,
                           CASE
                               WHEN actively_exploited=1 THEN 'P0-IMMEDIATE'
                               WHEN cvss_score>=9 AND has_exploit=1 THEN 'P1-URGENT'
                               WHEN cvss_score>=7 THEN 'P2-HIGH'
                               ELSE 'P3-MONITOR'
                           END as patch_priority
                    FROM cve
                    WHERE actively_exploited=1
                       OR (cvss_score>=9 AND has_exploit=1)
                    ORDER BY actively_exploited DESC,
                             COALESCE(cvss_score,0) DESC
                    LIMIT 20
                """).fetchall()

                total_cve   = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0] or 1
                p0_count    = c.execute("SELECT COUNT(*) FROM cve WHERE actively_exploited=1").fetchone()[0]
                kev_count   = p0_count
                crit_count  = c.execute("SELECT COUNT(*) FROM cve WHERE severity='CRITICAL'").fetchone()[0]

                kev_pct     = round(p0_count  / total_cve * 100, 1)
                crit_pct    = round(crit_count / total_cve * 100, 1)
                posture_score = max(10, 100 - min(50, int(kev_pct * 2)) - min(20, int(crit_pct)))
                posture_score = int(posture_score)

                if posture_score < 30:
                    posture_level = "CRITICAL"
                elif posture_score < 50:
                    posture_level = "HIGH"
                elif posture_score < 70:
                    posture_level = "MEDIUM"
                else:
                    posture_level = "LOW"

            return jsonify({
                "posture_score": posture_score,
                "posture_level": posture_level,
                "p0_immediate":  p0_count,
                "kev_active":    kev_count,
                "total_cve":     total_cve,
                "kev_rate":      kev_pct,
                "critical_rate": crit_pct,
                "by_attack_type": [],
                "top_priority":  [dict(r) for r in top_cves],
                "recommendations": [
                    {"priority": "P0", "action": f"Patch {p0_count} actively exploited CVEs immediately",
                     "impact": "Eliminates confirmed active exploitation risk"},
                    {"priority": "P1", "action": "Block metadata endpoints — SSRF protection (169.254.169.254)",
                     "impact": "Prevents lateral movement in cloud environments"},
                    {"priority": "P2", "action": "Enforce container security policies (non-root, read-only fs)",
                     "impact": "Prevents container escape attacks"},
                    {"priority": "P3", "action": "Enable SBOM + supply chain verification",
                     "impact": "Reduces dependency confusion and supply chain risk"},
                ]
            })
        except Exception as e:
            import traceback
            return jsonify({"error": str(e), "trace": traceback.format_exc()[-200:]}), 500


    @app.route("/api/v1/ioc/stats")
    def cloud_ioc_stats():
        try:
            from ioc_collector import get_ioc_stats
            return jsonify(get_ioc_stats())
        except Exception as e:
            return jsonify({"error": str(e), "total": 0}), 500

    @app.route("/api/v1/ioc")
    def cloud_ioc_list():
        try:
            ioc_type = request.args.get("type", "")
            verdict  = request.args.get("verdict", "")
            source   = request.args.get("source", "")
            limit    = int(request.args.get("limit", 100))
            offset   = int(request.args.get("offset", 0))

            with get_conn() as c:
                # Vérifier colonnes disponibles
                cols = [col[1] for col in c.execute("PRAGMA table_info(ioc)").fetchall()]
                has_vt = "vt_verdict" in cols

                q    = "SELECT * FROM ioc WHERE 1=1"
                args = []
                if ioc_type: q += " AND type=?";    args.append(ioc_type)
                if source:   q += " AND source=?";  args.append(source)
                if verdict and has_vt:
                    q += " AND vt_verdict=?"; args.append(verdict)

                total = c.execute(
                    q.replace("SELECT *","SELECT COUNT(*)"), args
                ).fetchone()[0]

                q += " ORDER BY id DESC LIMIT ? OFFSET ?"
                args += [limit, offset]
                rows = c.execute(q, args).fetchall()

            return jsonify({
                "data":   [dict(r) for r in rows],
                "total":  total,
                "limit":  limit,
                "offset": offset
            })
        except Exception as e:
            return jsonify({"error": str(e), "data": [], "total": 0}), 500

    @app.route("/api/v1/ioc/collect", methods=["POST"])
    def cloud_ioc_collect():
        import threading
        def do_collect():
            try:
                from ioc_collector import run_ioc_collector
                run_ioc_collector()
            except Exception as e:
                print(f"[IOC] Erreur: {e}")
        threading.Thread(target=do_collect, daemon=True).start()
        return jsonify({"status": "started"})

    @app.route("/api/v1/ioc/verify", methods=["POST"])
    def cloud_ioc_verify():
        """Vérifier les IOC pending via VT."""
        import threading
        def do_verify():
            try:
                from ioc_collector import verify_pending_iocs
                verify_pending_iocs(limit=30)
            except Exception as e:
                print(f"[VT] Erreur: {e}")
        threading.Thread(target=do_verify, daemon=True).start()
        return jsonify({"status": "started"})


    @app.route("/api/v1/scheduler/status")
    def scheduler_status():
        """État du scheduler et dernières collectes."""
        try:
            from database import get_conn
            import datetime
            with get_conn() as c:
                total_cve  = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
                kev_count  = c.execute("SELECT COUNT(*) FROM cve WHERE actively_exploited=1").fetchone()[0]
                enriched   = c.execute("SELECT COUNT(*) FROM cve WHERE attack_type IS NOT NULL").fetchone()[0]
                ioc_total  = c.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
                ioc_mal    = c.execute("SELECT COUNT(*) FROM ioc WHERE vt_verdict='MALICIOUS'").fetchone()[0] if "vt_verdict" in [col[1] for col in c.execute("PRAGMA table_info(ioc)").fetchall()] else 0
                last_cve   = c.execute("SELECT MAX(created_at) FROM cve").fetchone()[0]
                last_inc   = c.execute("SELECT MAX(created_at) FROM incident").fetchone()[0]
                incidents  = c.execute("SELECT COUNT(*) FROM incident").fetchone()[0]

            import schedule
            jobs = [{"job": str(j.job_func.__name__), "next_run": str(j.next_run)} for j in schedule.jobs]

            return jsonify({
                "status": "running",
                "data": {
                    "cve_total":     total_cve,
                    "kev_total":     kev_count,
                    "cve_enriched":  enriched,
                    "ioc_total":     ioc_total,
                    "ioc_malicious": ioc_mal,
                    "incidents":     incidents,
                    "last_cve_update": last_cve,
                    "last_incident":   last_inc,
                },
                "scheduled_jobs": jobs,
                "sources": {
                    "nvd":       "https://nvd.nist.gov/developers/vulnerabilities",
                    "cisa_kev":  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "epss":      "https://www.first.org/epss/",
                    "urlhaus":   "https://urlhaus.abuse.ch/",
                    "feodo":     "https://feodotracker.abuse.ch/",
                    "threatfox": "https://threatfox.abuse.ch/",
                    "virustotal":"https://www.virustotal.com/",
                    "misp":      "https://localhost",
                    "leakcheck": "https://leakcheck.io/"
                }
            })
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)}), 500

    @app.route("/api/v1/scheduler/run/<task>", methods=["POST"])
    def scheduler_run_task(task):
        """Déclencher une tâche manuellement."""
        import threading
        tasks = {
            "cves":    "task_collect_cves",
            "enrich":  "task_enrich_cves",
            "iocs":    "task_collect_iocs",
            "vt":      "task_verify_vt",
            "misp":    "task_misp_sync",
            "kev":     "task_update_kev",
            "epss":    "task_update_epss",
        }
        if task not in tasks:
            return jsonify({"error": f"Unknown task. Available: {list(tasks.keys())}"}), 400
        try:
            from auto_scheduler import (task_collect_cves, task_enrich_cves,
                task_collect_iocs, task_verify_vt, task_misp_sync,
                task_update_kev, task_update_epss)
            fn_map = {
                "cves": task_collect_cves, "enrich": task_enrich_cves,
                "iocs": task_collect_iocs, "vt": task_verify_vt,
                "misp": task_misp_sync, "kev": task_update_kev,
                "epss": task_update_epss
            }
            threading.Thread(target=fn_map[task], daemon=True).start()
            return jsonify({"status": "started", "task": task})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    print("[API] Cloud + IOC endpoints enregistrés")
