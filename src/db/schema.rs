pub const CREATE_TABLES: &str = "
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    repo_path TEXT,
    intensity TEXT NOT NULL DEFAULT 'standard',
    provider TEXT NOT NULL DEFAULT 'anthropic',
    model TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    current_phase TEXT,
    current_agents TEXT,
    completed_agents TEXT,
    finding_count_critical INTEGER DEFAULT 0,
    finding_count_high INTEGER DEFAULT 0,
    finding_count_medium INTEGER DEFAULT 0,
    finding_count_low INTEGER DEFAULT 0,
    finding_count_info INTEGER DEFAULT 0,
    total_cost_usd REAL DEFAULT 0.0,
    total_duration_ms INTEGER DEFAULT 0,
    report_json TEXT,
    summary_md TEXT,
    error_message TEXT,
    config_path TEXT,
    webhook_url TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    recommendation TEXT,
    tool TEXT,
    technique TEXT,
    source TEXT,
    verdict TEXT,
    proof_of_exploit TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
";
