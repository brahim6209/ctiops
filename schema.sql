CREATE TABLE IF NOT EXISTS cve (
    id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    severity TEXT,
    published TEXT,
    modified TEXT,
    keywords TEXT,
    tlp TEXT DEFAULT 'TLP:WHITE',
    pushed_opencti INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS incident (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT, repo TEXT, actor TEXT,
    event_type TEXT, severity TEXT,
    raw_payload TEXT, mitre_id TEXT, mitre_name TEXT,
    tlp TEXT DEFAULT 'TLP:AMBER',
    ml_severity TEXT, anomaly_score REAL,
    pushed_opencti INTEGER DEFAULT 0,
    triggered_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ioc (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT, value TEXT UNIQUE,
    source TEXT, ml_score REAL,
    tlp TEXT DEFAULT 'TLP:AMBER',
    pushed_opencti INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS enrichment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value TEXT, provider TEXT,
    score REAL, malicious_count INTEGER,
    total_engines INTEGER, tags TEXT,
    enriched_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS recommendation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ref_id TEXT, ref_type TEXT,
    priority TEXT, title TEXT,
    description TEXT, mitre_id TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
