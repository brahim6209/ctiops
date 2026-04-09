#!/bin/bash
# CTIOps Universal Installer
# Usage: curl -s http://HOST:5000/install | bash

CTI_HOST=${CTI_HOST:-"http://localhost:5000"}
INSTALL_DIR=""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

log()     { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
info()    { echo -e "${CYAN}[i]${NC} $1"; }
section() { echo -e "\n${BOLD}${BLUE}── $1 ──${NC}"; }

echo -e "${BLUE}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║     CTIOps Universal Agent Installer  ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

section "Détection environnement"
if [ -n "$JENKINS_HOME" ] || [ -n "$BUILD_NUMBER" ]; then
    INSTALL_DIR="${JENKINS_HOME:-/var/lib/jenkins}/ctiops"
    info "Jenkins CI détecté"
elif [ -n "$GITLAB_CI" ]; then
    INSTALL_DIR="/tmp/ctiops"; info "GitLab CI détecté"
elif [ -n "$GITHUB_ACTIONS" ]; then
    INSTALL_DIR="/tmp/ctiops"; info "GitHub Actions détecté"
elif [ -f /.dockerenv ]; then
    INSTALL_DIR="/tmp/ctiops"; info "Docker détecté"
elif [ -w "/opt" ]; then
    INSTALL_DIR="/opt/ctiops"; info "Linux bare-metal détecté"
else
    INSTALL_DIR="$HOME/.ctiops"; info "Mode utilisateur"
fi

mkdir -p "$INSTALL_DIR/reports" "$INSTALL_DIR/processed" "$INSTALL_DIR/errors" 2>/dev/null || {
    INSTALL_DIR="$HOME/.ctiops"
    mkdir -p "$INSTALL_DIR/reports" "$INSTALL_DIR/processed" "$INSTALL_DIR/errors"
}
log "Installé dans : $INSTALL_DIR"

section "Installation agent"
cat > "$INSTALL_DIR/send.py" << 'PYEOF'
#!/usr/bin/env python3
import os, sys, shutil, json, urllib.request, hashlib
from datetime import datetime

def detect_config():
    return {
        'cti_host': os.environ.get('CTI_HOST') or os.environ.get('CTI_PLATFORM') or 'http://localhost:5000',
        'project':  os.environ.get('APP_NAME') or os.environ.get('CI_PROJECT_NAME') or
                    os.environ.get('GITHUB_REPOSITORY','').split('/')[-1] or
                    os.path.basename(os.environ.get('WORKSPACE', os.getcwd())),
        'build':    os.environ.get('BUILD_NUMBER') or os.environ.get('CI_PIPELINE_IID') or
                    os.environ.get('GITHUB_RUN_NUMBER') or datetime.utcnow().strftime('%Y%m%d%H%M'),
        'branch':   (os.environ.get('GIT_BRANCH') or os.environ.get('CI_COMMIT_REF_NAME') or
                    os.environ.get('GITHUB_REF_NAME') or 'main').replace('origin/',''),
        'repo':     os.environ.get('GIT_URL') or os.environ.get('CI_REPOSITORY_URL') or
                    os.environ.get('GITHUB_REPOSITORY') or '',
        'scan_dir': os.environ.get('APP_DIR') or os.environ.get('WORKSPACE') or
                    os.environ.get('CI_PROJECT_DIR') or os.environ.get('GITHUB_WORKSPACE') or os.getcwd(),
        'watch_dir': _find_watch_dir(),
    }

def _find_watch_dir():
    for c in [os.environ.get('CTI_WATCH_DIR',''),
              (os.environ.get('JENKINS_HOME','')+'/ctiops'),
              '/var/lib/jenkins/ctiops', '/opt/ctiops',
              '/tmp/ctiops', os.path.expanduser('~/.ctiops')]:
        if not c or c=='/ctiops': continue
        try:
            r = os.path.join(c,'reports')
            os.makedirs(r, exist_ok=True)
            t = os.path.join(r,'.test'); open(t,'w').close(); os.remove(t)
            return c
        except: continue
    d='/tmp/ctiops'; os.makedirs(d+'/reports',exist_ok=True); return d

REPORT_TOOLS = {
    'trivy-report.json':'trivy','trivy.json':'trivy',
    'gitleaks-report.json':'gitleaks','gitleaks.json':'gitleaks',
    'owasp-report.json':'owasp','dependency-check-report.json':'owasp',
    'zap-report.json':'owasp-zap','semgrep.json':'semgrep',
    'snyk.json':'snyk','grype.json':'grype','checkov-report.json':'checkov',
    'gl-sast-report.json':'semgrep','gl-dependency-scanning-report.json':'snyk',
}

def find_reports(scan_dir):
    found = []
    for root,dirs,files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules','.git','venv','__pycache__']]
        for f in files:
            if f in REPORT_TOOLS:
                found.append((os.path.join(root,f), REPORT_TOOLS[f]))
    return found

def send_http(filepath, tool, cfg):
    size = os.path.getsize(filepath)
    if size > 5*1024*1024: return None
    with open(filepath,'rb') as f: data = f.read()
    boundary = 'CTIOps-'+hashlib.md5(data[:100]).hexdigest()[:8]
    body = b''
    for k,v in [('project',cfg['project']),('build',str(cfg['build'])),
                ('branch',cfg['branch']),('repo',cfg['repo']),('tool',tool)]:
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    body += f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{os.path.basename(filepath)}"\r\nContent-Type: application/json\r\n\r\n'.encode()
    body += data + b'\r\n' + f'--{boundary}--\r\n'.encode()
    try:
        req = urllib.request.Request(f"{cfg['cti_host']}/api/v1/webhook/upload",
            data=body, headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
        resp = urllib.request.urlopen(req, timeout=60)
        return json.loads(resp.read().decode())
    except: return None

def drop_file(filepath, tool, cfg):
    dest = os.path.join(cfg['watch_dir'],'reports',cfg['project'],str(cfg['build']))
    os.makedirs(dest, exist_ok=True)
    shutil.copy2(filepath, os.path.join(dest, os.path.basename(filepath)))
    return dest

def main():
    cfg = detect_config()
    print(f"\n{'='*60}")
    print(f"  CTIOps Agent | project={cfg['project']} | build=#{cfg['build']}")
    print(f"  Host: {cfg['cti_host']} | Dir: {cfg['scan_dir']}")
    print(f"{'='*60}")
    reports = find_reports(cfg['scan_dir'])
    if not reports:
        print(f"  [WARN] Aucun rapport trouvé dans {cfg['scan_dir']}"); return
    print(f"  {len(reports)} rapport(s) trouvé(s)\n")
    for filepath, tool in reports:
        size_kb = os.path.getsize(filepath)//1024
        print(f"  [{tool.upper()}] {os.path.basename(filepath)} ({size_kb}KB)", end=' ... ', flush=True)
        r = send_http(filepath, tool, cfg)
        if r and r.get('status')=='ok':
            print(f"✓ HTTP | findings={r.get('total_findings',0)} | risk={r.get('risk_level','?')}")
        else:
            dest = drop_file(filepath, tool, cfg)
            print(f"✓ DROP | watcher processing...")
    print(f"\n{'='*60}")
    print(f"  Dashboard: {cfg['cti_host']}")
    print(f"{'='*60}\n")

if __name__=='__main__': main()
PYEOF

chmod +x "$INSTALL_DIR/send.py"
log "Agent : $INSTALL_DIR/send.py"

# Wrapper shell
cat > "$INSTALL_DIR/ctiops-send" << SHEOF
#!/bin/bash
export CTI_HOST=\${CTI_HOST:-"$CTI_HOST"}
export CTI_WATCH_DIR="$INSTALL_DIR"
python3 "$INSTALL_DIR/send.py" "\$@"
SHEOF
chmod +x "$INSTALL_DIR/ctiops-send"

# Symlink global si possible
for BIN in /usr/local/bin "$HOME/.local/bin"; do
    if [ -w "$BIN" ] 2>/dev/null || mkdir -p "$BIN" 2>/dev/null; then
        ln -sf "$INSTALL_DIR/ctiops-send" "$BIN/ctiops-send" 2>/dev/null && \
            log "Commande globale: ctiops-send" && break
    fi
done

section "Installation terminée"
echo ""
echo -e "  ${GREEN}${BOLD}CTIOps Agent installé !${NC}"
echo ""
echo -e "  ${BOLD}Utilisation :${NC}"
echo "    python3 $INSTALL_DIR/send.py"
echo ""
echo -e "  ${BOLD}Avec variables :${NC}"
echo "    CTI_HOST=$CTI_HOST APP_NAME=monprojet BUILD_NUMBER=1 \\"
echo "    APP_DIR=/chemin/rapports python3 $INSTALL_DIR/send.py"
echo ""
echo -e "  ${BOLD}Réinstaller depuis n'importe où :${NC}"
echo -e "    ${CYAN}curl -s $CTI_HOST/install | bash${NC}"
echo ""
