#!/bin/bash
# ╔══════════════════════════════════════════════════════╗
# ║  CTIOps Universal Agent                              ║
# ║  Fonctionne : Docker, bare-metal, remote, CI/CD      ║
# ║  Usage: curl -s http://CTI_HOST:5000/agent | bash    ║
# ╚══════════════════════════════════════════════════════╝

CTI_URL=${CTI_PLATFORM:-"http://localhost:5000"}
PROJECT=${APP_NAME:-$(basename $(pwd))}
BUILD=${BUILD_NUMBER:-$(date +%s)}
BRANCH=${GIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")}
REPO=${GIT_URL:-$(git remote get-url origin 2>/dev/null || echo "")}
SCAN_DIR=${APP_DIR:-$(pwd)}

echo "╔══════════════════════════════════════╗"
echo "║  CTIOps Agent — Universal Scanner    ║"
echo "║  Project : $PROJECT"
echo "║  Build   : #$BUILD"
echo "║  Target  : $CTI_URL"
echo "╚══════════════════════════════════════╝"

send_report() {
    local FILE=$1
    local TOOL=$2
    if [ ! -f "$FILE" ] || [ ! -s "$FILE" ]; then
        echo "  [SKIP] $TOOL — not found"
        return
    fi
    RESULT=$(curl -s -X POST "$CTI_URL/api/v1/webhook/auto" \
        -H "Content-Type: application/json" \
        -d "{
            \"tool\":    \"$TOOL\",
            \"project\": \"$PROJECT\",
            \"build\":   \"$BUILD\",
            \"branch\":  \"$BRANCH\",
            \"repo\":    \"$REPO\",
            \"report\":  $(cat $FILE)
        }" 2>/dev/null)
    FINDINGS=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_findings',0))" 2>/dev/null || echo "?")
    RISK=$(echo $RESULT    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('risk_level','?'))" 2>/dev/null || echo "?")
    CATS=$(echo $RESULT    | python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.get('categories',{}).keys())[:3])" 2>/dev/null || echo "")
    echo "  [OK] $TOOL | findings=$FINDINGS | risk=$RISK | categories=$CATS"
}

# Auto-détection et envoi de tous les rapports trouvés
declare -A REPORT_MAP=(
    ["trivy-report.json"]="trivy"
    ["trivy.json"]="trivy"
    ["gitleaks-report.json"]="gitleaks"
    ["gitleaks.json"]="gitleaks"
    ["owasp-report.json"]="owasp"
    ["dependency-check-report.json"]="owasp"
    ["zap-report.json"]="owasp-zap"
    ["zap.json"]="owasp-zap"
    ["semgrep.json"]="semgrep"
    ["semgrep-report.json"]="semgrep"
    ["snyk.json"]="snyk"
    ["snyk-report.json"]="snyk"
    ["grype.json"]="grype"
    ["grype-report.json"]="grype"
    ["checkov-report.json"]="checkov"
    ["sonar-report.json"]="sonarqube"
    ["gl-sast-report.json"]="semgrep"
    ["gl-dependency-scanning-report.json"]="snyk"
    ["results.sarif"]="sarif"
)

FOUND=0
for FILENAME in "${!REPORT_MAP[@]}"; do
    TOOL="${REPORT_MAP[$FILENAME]}"
    # Cherche dans le répertoire courant et sous-répertoires
    for FOUND_FILE in $(find "$SCAN_DIR" -name "$FILENAME" 2>/dev/null | head -3); do
        send_report "$FOUND_FILE" "$TOOL"
        FOUND=$((FOUND+1))
    done
done

if [ $FOUND -eq 0 ]; then
    echo "  [WARN] No scan reports found in $SCAN_DIR"
    echo "  Tip: Run your scanners first, then re-run this agent"
fi

echo ""
echo "=== CTIOps Agent Done — $FOUND report(s) sent ==="
echo "    Dashboard: $CTI_URL"
