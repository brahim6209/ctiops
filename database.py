"""database.py — SQLite local CTI"""
import sqlite3, os

DB_PATH     = os.path.join(os.path.dirname(__file__), "data", "cti.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        with open(SCHEMA_PATH) as f:
            conn.executescript(f.read())
    print(f"[DB] Initialisée : {DB_PATH}")

def insert_cve(cve: dict):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO cve
            (id, description, cvss_score, cvss_vector, severity, published, modified, keywords, tlp)
            VALUES (:id,:description,:cvss_score,:cvss_vector,:severity,:published,:modified,:keywords,:tlp)
        """, cve)

def insert_incident(inc: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO incident
            (source, repo, actor, event_type, severity, raw_payload, mitre_id, mitre_name, tlp, ml_severity, anomaly_score, triggered_at)
            VALUES (:source,:repo,:actor,:event_type,:severity,:raw_payload,:mitre_id,:mitre_name,:tlp,:ml_severity,:anomaly_score,:triggered_at)
        """, inc)
        return cur.lastrowid

def insert_ioc(ioc: dict):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO ioc (type, value, source, tlp)
            VALUES (:type,:value,:source,:tlp)
        """, ioc)

def insert_enrichment(e: dict):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO enrichment
            (ioc_value, provider, score, malicious_count, total_engines, tags)
            VALUES (:ioc_value,:provider,:score,:malicious_count,:total_engines,:tags)
        """, e)

def insert_recommendation(r: dict):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO recommendation (ref_id, ref_type, priority, title, description, mitre_id)
            VALUES (:ref_id,:ref_type,:priority,:title,:description,:mitre_id)
        """, r)

def get_unpushed(table: str) -> list:
    with get_conn() as conn:
        return conn.execute(f"SELECT * FROM {table} WHERE pushed_opencti=0 LIMIT 50").fetchall()

def mark_pushed(table: str, record_id):
    with get_conn() as conn:
        conn.execute(f"UPDATE {table} SET pushed_opencti=1 WHERE id=?", (record_id,))

def get_stats() -> dict:
    with get_conn() as conn:
        return {
            "total_cve":       conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0],
            "critical_cve":    conn.execute("SELECT COUNT(*) FROM cve WHERE severity='CRITICAL'").fetchone()[0],
            "total_incidents": conn.execute("SELECT COUNT(*) FROM incident").fetchone()[0],
            "total_ioc":       conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0],
            "malicious_ioc":   conn.execute("SELECT COUNT(DISTINCT ioc_value) FROM enrichment WHERE score>50").fetchone()[0],
        }
