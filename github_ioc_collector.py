"""
GitHub IOC Collector — Sources d'exploits PoC dynamiques.
Pour chaque CVE critique, cherche les repos PoC GitHub
et extrait les IOC (URLs, IPs dans README, C2 potentiels).
"""
import requests, urllib3, re, time
from database import get_conn
urllib3.disable_warnings()

GH_BASE = "https://api.github.com"

def search_github_poc(cve_id: str) -> list:
    """Chercher repos PoC GitHub pour une CVE."""
    results = []
    try:
        r = requests.get(f"{GH_BASE}/search/repositories",
            params={"q": cve_id, "sort": "updated", "per_page": 10},
            timeout=15)
        if r.status_code == 200:
            for repo in (r.json().get('items') or [])[:8]:
                results.append({
                    "full_name"  : repo.get('full_name',''),
                    "url"        : repo.get('html_url',''),
                    "stars"      : repo.get('stargazers_count', 0),
                    "description": repo.get('description','') or '',
                    "updated"    : repo.get('updated_at','')[:10],
                    "language"   : repo.get('language',''),
                })
        time.sleep(0.5)
    except Exception as e:
        print(f"[GitHub] Error {cve_id}: {e}")
    return results

def extract_iocs_from_readme(owner: str, repo: str) -> list:
    """Extraire IPs/domaines depuis le README d'un repo."""
    iocs = []
    try:
        r = requests.get(
            f"{GH_BASE}/repos/{owner}/{repo}/readme",
            headers={"Accept": "application/vnd.github.raw"},
            timeout=10
        )
        if r.status_code == 200:
            content = r.text
            # Extraire IPs
            ips = re.findall(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                content
            )
            # Filtrer IPs privées/localhost
            public_ips = [ip for ip in ips if not (
                ip.startswith('127.') or ip.startswith('192.168.') or
                ip.startswith('10.') or ip.startswith('172.') or
                ip == '0.0.0.0'
            )]
            for ip in set(public_ips)[:5]:
                iocs.append({"type": "ip", "value": ip, "context": "README"})

            # Extraire domaines suspects
            domains = re.findall(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
                r'+(?:xyz|ru|cn|tk|ml|ga|cf|pw|top|cc|su)\b',
                content
            )
            for d in set(domains)[:3]:
                iocs.append({"type": "domain", "value": d, "context": "README"})

        time.sleep(0.3)
    except:
        pass
    return iocs

def collect_github_iocs_for_cves(limit: int = 5):
    """Collecter IOC GitHub pour les CVE critiques du pipeline."""
    # CVE critiques Trivy
    with get_conn() as c:
        cves = c.execute("""
            SELECT DISTINCT json_extract(i.details,'$.cve_id') as cve_id,
                   c.reality_score, c.attack_type, c.has_exploit
            FROM incident i
            LEFT JOIN cve c ON json_extract(i.details,'$.cve_id') = c.id
            WHERE i.source='trivy'
            AND c.severity='CRITICAL'
            AND c.reality_score > 50
            ORDER BY c.reality_score DESC
            LIMIT ?
        """, (limit,)).fetchall()

    total_added = 0
    results = []

    for cve_row in cves:
        cve_id = cve_row['cve_id']
        if not cve_id:
            continue

        print(f"[GitHub] Recherche PoC pour {cve_id}...")
        repos = search_github_poc(cve_id)

        cve_result = {
            "cve_id"      : cve_id,
            "reality_score": cve_row['reality_score'],
            "attack_type" : cve_row['attack_type'],
            "github_pocs" : [],
            "iocs_found"  : []
        }

        for repo in repos:
            poc_info = {
                "repo"   : repo['full_name'],
                "url"    : repo['url'],
                "stars"  : repo['stars'],
                "lang"   : repo['language'],
                "updated": repo['updated'],
                "desc"   : repo['description'][:80]
            }
            cve_result['github_pocs'].append(poc_info)

            # Sauvegarder URL PoC comme IOC dans DB
            with get_conn() as c:
                try:
                    c.execute("""
                        INSERT OR IGNORE INTO ioc
                        (type, value, source, ml_score, tlp, vt_verdict)
                        VALUES ('url', ?, 'GitHub-PoC', ?, 'TLP:WHITE', 'PENDING')
                    """, (repo['url'],
                          min(1.0, 0.5 + repo['stars'] * 0.01)))
                    total_added += 1
                except:
                    pass

            # Extraire IOC du README si repo populaire
            if repo['stars'] >= 1:
                owner, rname = repo['full_name'].split('/', 1)
                readme_iocs = extract_iocs_from_readme(owner, rname)
                for ioc in readme_iocs:
                    cve_result['iocs_found'].append(ioc)
                    with get_conn() as c:
                        try:
                            c.execute("""
                                INSERT OR IGNORE INTO ioc
                                (type, value, source, ml_score, tlp, vt_verdict)
                                VALUES (?, ?, 'GitHub-README', 0.7, 'TLP:WHITE', 'PENDING')
                            """, (ioc['type'], ioc['value']))
                            total_added += 1
                        except:
                            pass

        results.append(cve_result)
        print(f"  → {len(repos)} PoC | {len(cve_result['iocs_found'])} IOC extraits")

    print(f"[GitHub] Total: {total_added} IOC ajoutés en DB")
    return results

def register_github_routes(app):
    from flask import request, jsonify

    @app.route("/api/v1/github/pocs")
    def api_github_pocs():
        """PoC GitHub pour les CVE critiques pipeline."""
        limit = int(request.args.get('limit', 5))
        results = collect_github_iocs_for_cves(limit)
        return jsonify({
            "cves"       : results,
            "total_cves" : len(results),
            "total_pocs" : sum(len(r['github_pocs']) for r in results),
            "source"     : "GitHub API — repos PoC par CVE ID"
        })

    @app.route("/api/v1/github/pocs/<cve_id>")
    def api_github_poc_cve(cve_id):
        """PoC GitHub pour une CVE spécifique."""
        repos  = search_github_poc(cve_id)
        all_iocs = []
        for repo in repos[:3]:
            if repo['stars'] >= 1:
                owner, rname = repo['full_name'].split('/', 1)
                iocs = extract_iocs_from_readme(owner, rname)
                all_iocs.extend(iocs)
        return jsonify({
            "cve_id"     : cve_id,
            "github_pocs": repos,
            "iocs"       : all_iocs,
            "total_pocs" : len(repos),
            "source"     : "GitHub API"
        })
