PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS scans (
    id               TEXT PRIMARY KEY,            -- uuid4 hex
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_name      TEXT NOT NULL,
    scope            TEXT,
    engagement_dates TEXT,
    nmap_file        TEXT,
    burp_file        TEXT,
    sqlmap_file      TEXT,
    llm_provider     TEXT NOT NULL DEFAULT 'anthropic',
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','ingesting','correlating',
                                       'scoring','writing','complete','failed')),
    error_summary    TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT NOT NULL,               -- VAPT-2026-001
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_tool     TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INTEGER,
    protocol        TEXT DEFAULT 'tcp',
    service         TEXT,
    url             TEXT,
    parameter       TEXT,
    finding_type    TEXT NOT NULL,
    name            TEXT NOT NULL,
    severity        TEXT CHECK (severity IN ('Critical','High','Medium','Low','Informational')),
    cvss_vector     TEXT,
    cvss_score      REAL CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    score_disputed  INTEGER NOT NULL DEFAULT 0,
    confidence      TEXT,
    description     TEXT,
    business_impact TEXT,
    evidence        TEXT,
    remediation     TEXT,                        -- JSON array of step strings
    refs            TEXT,                        -- JSON array of CWE/OWASP/CVE ids
    instances       INTEGER NOT NULL DEFAULT 1,
    is_chain_member INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, id)
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id              TEXT PRIMARY KEY,            -- uuid4 hex
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    chain_name      TEXT NOT NULL,
    finding_ids     TEXT NOT NULL,               -- JSON array, in attack order
    combined_impact TEXT,
    detected_by     TEXT NOT NULL DEFAULT 'rule'
                    CHECK (detected_by IN ('rule','llm','rule+llm'))
);

CREATE TABLE IF NOT EXISTS reports (
    id              TEXT PRIMARY KEY,            -- uuid4 hex
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    format          TEXT NOT NULL CHECK (format IN ('pdf','md','html')),
    file_path       TEXT NOT NULL,
    finding_count   INTEGER NOT NULL,
    severity_counts TEXT,                        -- JSON {"Critical":1,...}
    llm_model       TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(scan_id, cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_host     ON findings(scan_id, host, port);
CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_chains_scan       ON attack_chains(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan      ON reports(scan_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created     ON scans(created_at DESC);
