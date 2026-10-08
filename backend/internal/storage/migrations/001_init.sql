-- EXPOSE Security Intelligence Platform
-- PostgreSQL Initial Schema Migration (001_init.sql)

CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain);

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    raw_target TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    overall_score INT,
    letter_grade VARCHAR(5),
    confirmed_flaws_count INT DEFAULT 0,
    observed_properties_count INT DEFAULT 0,
    category_scores JSONB,
    severity_counts JSONB,
    probe_statuses JSONB,
    not_assessed_boundaries JSONB,
    duration_seconds DOUBLE PRECISION,
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(100) PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    probe VARCHAR(100) NOT NULL,
    target TEXT NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    confidence VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL, -- CONFIRMED, OBSERVED, INFERRED, NOT_ASSESSED
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    impact_explanation TEXT,
    remediation TEXT NOT NULL,
    verification_command TEXT,
    cwe_id VARCHAR(50),
    cve_id VARCHAR(50),
    evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    client_ip VARCHAR(100) NOT NULL,
    user_agent TEXT,
    action VARCHAR(100) NOT NULL,
    authorized_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    details JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_scan_id ON audit_logs(scan_id);
