import json
from flask import request, jsonify
from database import get_conn

def register_devsecops_cve_routes(app):

    @app.route("/api/v1/devsecops/cve-enriched")
    def api_devsecops_cve_enriched():
        build    = request.args.get("build", "")
        severity = request.args.get("severity", "")
        limit    = int(request.args.get("limit", 100))
        offset   = int(request.args.get("offset", 0))

        with get_conn() as conn:
            where = "WHERE i.source='trivy'"
            params = []
            if build:
                where += " AND json_extract(i.details,'$.build')=?"
                params.append(str(build))
            if severity:
                where += " AND i.severity=?"
                params.append(severity)

            total = conn.execute(
                f"SELECT COUNT(*) FROM incident i {where}", params
            ).fetchone()[0]

            sql = f"""
                SELECT i.id, i.severity, i.mitre_id, i.created_at,
                    json_extract(i.details,'$.cve_id') as cve_id,
                    json_extract(i.details,'$.package') as package,
                    json_extract(i.details,'$.version') as version,
                    json_extract(i.details,'$.fixed_version') as fixed_version,
                    json_extract(i.details,'$.cvss_score') as trivy_cvss,
                    json_extract(i.details,'$.description') as description,
                    json_extract(i.details,'$.vuln_type') as vuln_type,
                    json_extract(i.details,'$.build') as build,
                    c.cvss_score as nvd_cvss,
                    c.epss_score, c.epss_percentile,
                    c.reality_score, c.actively_exploited,
                    c.has_exploit, c.exploit_source,
                    c.attack_type, c.mitre_technique,
                    c.description as nvd_description
                FROM incident i
                LEFT JOIN cve c ON json_extract(i.details,'$.cve_id') = c.id
                {where}
                ORDER BY COALESCE(c.reality_score,0) DESC,
                         COALESCE(c.epss_score,0) DESC
                LIMIT ? OFFSET ?
            """
            rows = conn.execute(sql, params + [limit, offset]).fetchall()

        results = []
        for r in rows:
            d = dict(r)
            results.append({
                "id": d["id"],
                "cve_id": d["cve_id"],
                "package": d["package"],
                "version": d["version"],
                "fixed_version": d["fixed_version"],
                "severity": d["severity"],
                "build": d["build"],
                "mitre_id": d["mitre_id"],
                "trivy_cvss": d["trivy_cvss"],
                "vuln_type": d["vuln_type"],
                "description": d["nvd_description"] or d["description"],
                "cvss_score": d["nvd_cvss"] or d["trivy_cvss"],
                "epss_score": d["epss_score"] or 0,
                "reality_score": d["reality_score"] or 0,
                "actively_exploited": bool(d["actively_exploited"]),
                "has_exploit": bool(d["has_exploit"]),
                "exploit_source": d["exploit_source"],
                "attack_type": d["attack_type"] or d["vuln_type"] or "CVE",
                "mitre_technique": d["mitre_technique"] or d["mitre_id"],
                "in_nvd": d["nvd_cvss"] is not None,
            })

        return jsonify({"data": results, "total": total})
