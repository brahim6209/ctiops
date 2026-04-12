"""
patch_rl_recommender.py — Reinforcement Learning pour recommandation de correctifs
Algorithme: Q-Learning (sans dépendance stable-baselines3)
State:  vecteur de CVE actives (cvss, epss, kev, attack_type_score, has_exploit)
Action: index de la CVE à patcher en premier
Reward: risk_reduced - 0.1 * patch_cost
"""
import numpy as np
import json
from database import get_conn

# ── ATTACK TYPE RISK SCORES ──────────────────────────────────────
ATTACK_RISK = {
    'RCE': 15, 'SSRF': 12, 'AUTH_BYPASS': 13, 'PRIVESC': 11,
    'SQLI': 10, 'PATH_TRAVERSAL': 9, 'SUPPLY_CHAIN': 8,
    'CONTAINER_ESCAPE': 14, 'INFO_DISCLOSURE': 6,
    'CLOUD_SPECIFIC': 7, 'DOS': 5, 'UNKNOWN': 3
}

# ── DEPENDENCY GRAPH ─────────────────────────────────────────────
# CVE A dépend de CVE B = patcher B réduit aussi risque de A
DEPENDENCY_RULES = {
    'SUPPLY_CHAIN':     ['RCE', 'PRIVESC'],      # supply chain → peut mener à RCE
    'AUTH_BYPASS':      ['PRIVESC', 'RCE'],       # auth bypass → privesc/rce
    'INFO_DISCLOSURE':  ['AUTH_BYPASS', 'SQLI'],  # info disclosure → credential theft
    'SSRF':             ['RCE', 'CLOUD_SPECIFIC'],# ssrf → cloud metadata → RCE
    'PATH_TRAVERSAL':   ['RCE', 'INFO_DISCLOSURE'],
}

def compute_risk_score(cve: dict) -> float:
    """Score de risque composite pour une CVE."""
    cvss   = float(cve.get('cvss_score') or 0) / 10.0
    epss   = float(cve.get('epss_score') or 0)
    kev    = 1.0 if cve.get('actively_exploited') else 0.0
    exploit= 0.5 if cve.get('has_exploit') else 0.0
    atype  = ATTACK_RISK.get(cve.get('attack_type') or 'UNKNOWN', 3) / 15.0
    reality= float(cve.get('reality_score') or 0) / 100.0

    # Pondération
    return (cvss * 0.25 + epss * 0.25 + kev * 0.20 +
            exploit * 0.10 + atype * 0.10 + reality * 0.10)

def compute_dependency_bonus(cve: dict, all_cves: list) -> float:
    """
    Bonus si patcher cette CVE réduit aussi le risque d'autres CVE.
    Implémente le concept RL : récompense cascade.
    """
    atype = cve.get('attack_type', 'UNKNOWN')
    bonus = 0.0
    # Chercher les CVE qui dépendent de ce type
    for other in all_cves:
        if other['id'] == cve['id']:
            continue
        other_type = other.get('attack_type', 'UNKNOWN')
        # Si l'autre CVE est dans la liste des dépendants
        for dep_type, enables in DEPENDENCY_RULES.items():
            if atype == dep_type and other_type in enables:
                bonus += compute_risk_score(other) * 0.3  # 30% du risque cascade
    return min(bonus, 0.5)  # cap à 0.5

def estimate_patch_cost(cve: dict) -> float:
    """
    Coût estimé du patch (0.0 → 1.0).
    CISA KEV = coût élevé (production impactée)
    Has fix = coût faible
    """
    cost = 0.3  # baseline
    if cve.get('actively_exploited'): cost += 0.3   # urgence = coût opérationnel
    if cve.get('has_exploit'):        cost += 0.2   # patch critique = risque déploiement
    # Si fix disponible dans le package, coût réduit
    fixed = cve.get('fixed_version') or ''
    if fixed and fixed != 'N/A':     cost -= 0.2   # fix dispo = patch simple
    return max(0.1, min(1.0, cost))

# ── Q-LEARNING AGENT ─────────────────────────────────────────────
class PatchRLAgent:
    """
    Q-Learning agent pour optimiser l'ordre de patching.
    State:  top-N CVE représentées par leurs features
    Action: index de la CVE à patcher
    Reward: risk_reduced + dependency_bonus - 0.1 * patch_cost
    """

    def __init__(self, n_actions=10, learning_rate=0.1, discount=0.95, epsilon=0.1, seed=42):
        self.n  = n_actions
        self.lr = learning_rate
        self.gamma   = discount
        self.epsilon = epsilon
        self.q_table: dict = {}  # state_key → [Q-values par action]
        np.random.seed(seed)  # reproductibilité

    def _state_key(self, cves: list) -> str:
        """Représentation discrète de l'état pour Q-table."""
        key_parts = []
        for cve in cves[:self.n]:
            cvss_b  = int(float(cve.get('cvss_score') or 0) / 2)   # 0-5
            epss_b  = int(float(cve.get('epss_score') or 0) * 5)   # 0-5
            kev_b   = 1 if cve.get('actively_exploited') else 0
            key_parts.append(f"{cvss_b}{epss_b}{kev_b}")
        return '|'.join(key_parts)

    def get_q_values(self, state_key: str, n_actions: int) -> np.ndarray:
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(n_actions)
        return self.q_table[state_key]

    def select_action(self, cves: list) -> int:
        """Epsilon-greedy action selection."""
        n = min(len(cves), self.n)
        if n == 0: return 0
        if np.random.random() < self.epsilon:
            return np.random.randint(n)
        state_key = self._state_key(cves)
        q_vals = self.get_q_values(state_key, n)
        return int(np.argmax(q_vals[:n]))

    def train_episode(self, cves_input: list) -> float:
        """Un épisode = ordonner toutes les CVE de patch."""
        cves      = [dict(c) for c in cves_input]
        total_reward = 0.0

        for _ in range(len(cves)):
            if not cves: break

            state_key = self._state_key(cves)
            n_actions = min(len(cves), self.n)
            action    = self.select_action(cves)
            action    = min(action, len(cves)-1)

            chosen = cves[action]

            # Reward = risk réduit + cascade - coût
            risk    = compute_risk_score(chosen)
            cascade = compute_dependency_bonus(chosen, cves)
            cost    = estimate_patch_cost(chosen)
            reward  = risk + cascade - 0.1 * cost

            total_reward += reward

            # Q-update
            q_vals = self.get_q_values(state_key, n_actions)
            remaining = [c for i,c in enumerate(cves) if i != action]
            if remaining:
                next_key  = self._state_key(remaining)
                next_q    = self.get_q_values(next_key, min(len(remaining), self.n))
                target    = reward + self.gamma * np.max(next_q)
            else:
                target    = reward
            q_vals[action] += self.lr * (target - q_vals[action])

            cves = remaining

        return total_reward

    def train(self, cves: list, episodes=200) -> dict:
        """Entraîner l'agent sur les CVE actuelles."""
        rewards = []
        for ep in range(episodes):
            r = self.train_episode(cves)
            rewards.append(r)
            # Decay epsilon
            self.epsilon = max(0.01, self.epsilon * 0.995)
        return {
            'episodes': episodes,
            'avg_reward': round(float(np.mean(rewards[-20:])), 3),
            'convergence': round(float(np.std(rewards[-20:])), 3),
        }

# ── MAIN RECOMMENDER ─────────────────────────────────────────────
_agent: PatchRLAgent | None = None

def get_patch_recommendations(build: str = '', limit: int = 15) -> dict:
    """
    Générer l'ordre optimal de patching via RL.
    Retourne les CVE triées par ordre de priorité RL.
    """
    global _agent

    # Charger les CVE du build (ou globales)
    with get_conn() as c:
        if build:
            rows = c.execute("""
                SELECT DISTINCT
                    c.id, c.cvss_score, c.epss_score, c.severity,
                    c.actively_exploited, c.has_exploit, c.attack_type,
                    c.reality_score, c.description,
                    json_extract(i.details,'$.fixed_version') as fixed_version,
                    json_extract(i.details,'$.package') as package,
                    json_extract(i.details,'$.build') as build_num
                FROM incident i
                LEFT JOIN cve c ON json_extract(i.details,'$.cve_id') = c.id
                WHERE i.source IN ('trivy','owasp')
                AND json_extract(i.details,'$.build')=?
                AND c.id IS NOT NULL
                ORDER BY COALESCE(c.reality_score,0) DESC
                LIMIT ?
            """, (str(build), limit)).fetchall()
        else:
            rows = c.execute("""
                SELECT id, cvss_score, epss_score, severity,
                       actively_exploited, has_exploit, attack_type,
                       reality_score, description,
                       NULL as fixed_version, NULL as package, NULL as build_num
                FROM cve
                WHERE severity IN ('CRITICAL','HIGH')
                AND attack_type IS NOT NULL
                ORDER BY COALESCE(reality_score,0) DESC
                LIMIT ?
            """, (limit,)).fetchall()

    cves = [dict(r) for r in rows]
    if not cves:
        return {'recommendations': [], 'model': 'rl_no_data', 'build': build}

    # Entraîner l'agent RL
    if _agent is None:
        _agent = PatchRLAgent(n_actions=min(len(cves), 10))
    
    training_stats = _agent.train(cves, episodes=300)

    # Générer l'ordre optimal
    remaining = [dict(c) for c in cves]
    ordered   = []
    patch_order = 1

    while remaining:
        action = _agent.select_action(remaining)
        action = min(action, len(remaining)-1)
        chosen = remaining[action]

        risk    = compute_risk_score(chosen)
        cascade = compute_dependency_bonus(chosen, remaining)
        cost    = estimate_patch_cost(chosen)

        # Dépendances impactées
        deps_impacted = []
        atype = chosen.get('attack_type','UNKNOWN')
        for dep_type, enables in DEPENDENCY_RULES.items():
            if atype == dep_type:
                for other in remaining:
                    if other.get('attack_type') in enables and other['id'] != chosen['id']:
                        deps_impacted.append(other['id'])

        ordered.append({
            'patch_order':     patch_order,
            'cve_id':          chosen['id'],
            'package':         chosen.get('package') or '',
            'severity':        chosen.get('severity','UNKNOWN'),
            'attack_type':     chosen.get('attack_type','UNKNOWN'),
            'cvss_score':      chosen.get('cvss_score'),
            'epss_score':      chosen.get('epss_score'),
            'reality_score':   chosen.get('reality_score'),
            'actively_exploited': bool(chosen.get('actively_exploited')),
            'has_exploit':     bool(chosen.get('has_exploit')),
            'fixed_version':   chosen.get('fixed_version') or '',
            'rl_risk_score':   round(risk, 3),
            'rl_cascade_bonus':round(cascade, 3),
            'rl_patch_cost':   round(cost, 3),
            'rl_total_reward': round(risk + cascade - 0.1*cost, 3),
            'dependencies_impacted': deps_impacted[:3],
            'patch_rationale': _get_rationale(chosen, cascade, deps_impacted),
            'description':     (chosen.get('description') or '')[:120],
        })

        remaining = [c for i,c in enumerate(remaining) if i != action]
        patch_order += 1

    # Statistiques globales
    total_risk_before = sum(compute_risk_score(c) for c in cves)
    total_risk_after  = 0.0  # après patching optimal = 0

    return {
        'recommendations':    ordered,
        'total_cves':         len(cves),
        'total_risk_before':  round(total_risk_before, 3),
        'risk_reduction_pct': 100,
        'model':              'Q-Learning RL (custom)',
        'training':           training_stats,
        'build':              build,
        'algorithm': {
            'name':        'Q-Learning',
            'state_space': 'CVE risk vectors (CVSS × EPSS × KEV × attack_type)',
            'action_space': f'{min(len(cves),10)} CVE patch actions',
            'reward':      'risk_reduced + cascade_bonus - 0.1 × patch_cost',
            'episodes':    training_stats['episodes'],
            'convergence': training_stats['convergence'],
        }
    }

def _get_rationale(cve: dict, cascade: float, deps: list) -> str:
    """Explication textuelle de la recommandation RL."""
    reasons = []
    if cve.get('actively_exploited'):
        reasons.append("CISA KEV — actively exploited in the wild")
    if float(cve.get('epss_score') or 0) > 0.5:
        reasons.append(f"EPSS {float(cve.get('epss_score',0))*100:.0f}% exploitation probability")
    if cascade > 0.1:
        reasons.append(f"Cascade: reduces risk of {len(deps)} dependent CVE(s)")
    if cve.get('has_exploit'):
        reasons.append("Public exploit available")
    atype = cve.get('attack_type','')
    if atype in ('RCE','CONTAINER_ESCAPE','AUTH_BYPASS'):
        reasons.append(f"High-impact attack type: {atype}")
    return ' · '.join(reasons) if reasons else "RL optimal sequencing"

if __name__ == '__main__':
    print("=== RL Patch Recommender Test ===")
    result = get_patch_recommendations(limit=10)
    print(f"Model:    {result['model']}")
    print(f"Training: {result['training']}")
    print(f"\nOptimal patch order:")
    for r in result['recommendations']:
        cascade_info = f" [cascades {r['dependencies_impacted']}]" if r['dependencies_impacted'] else ""
        print(f"  #{r['patch_order']} {r['cve_id']:20} reward={r['rl_total_reward']:.3f}{cascade_info}")
        print(f"      → {r['patch_rationale']}")
