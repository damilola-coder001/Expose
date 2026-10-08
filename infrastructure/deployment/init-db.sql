-- ==============================================================================
-- EXPOSE Security Intelligence Platform — Relational Schema (init-db.sql)
-- Phase 2 Domain Model Specification
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Target domain entities
CREATE TABLE IF NOT EXISTS targets (
    id VARCHAR(50) PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    default_port INT NOT NULL DEFAULT 443,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain);

-- Security assessment scan instances
CREATE TABLE IF NOT EXISTS scans (
    id VARCHAR(50) PRIMARY KEY,
    target_id VARCHAR(50) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    raw_target TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    score_card JSONB,
    risk_assessment JSONB,
    severity_counts JSONB,
    duration_seconds DOUBLE PRECISION DEFAULT 0.0,
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);

-- Empirical findings verified with raw wire evidence
CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(100) PRIMARY KEY,
    scan_id VARCHAR(50) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(30) NOT NULL,
    confidence VARCHAR(30) NOT NULL,
    status VARCHAR(30) NOT NULL, -- CONFIRMED, OBSERVED, INFERRED, NOT_ASSESSED
    category VARCHAR(50) NOT NULL,
    rule_id VARCHAR(100) NOT NULL,
    owasp_mapping VARCHAR(100),
    asvs_mapping VARCHAR(100),
    cwe VARCHAR(50),
    cve VARCHAR(50),
    evidence JSONB NOT NULL,
    impact TEXT,
    recommendation JSONB NOT NULL,
    verification JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Discovered observable assets
CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(50) PRIMARY KEY,
    target_id VARCHAR(50) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- HOST, IP_ADDRESS, CERTIFICATE, ENDPOINT, HEADER
    value TEXT NOT NULL,
    attributes JSONB,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_target_id ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);

-- Immutable audit ledger
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id VARCHAR(50) REFERENCES scans(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    client_ip VARCHAR(100) NOT NULL,
    user_agent TEXT,
    action VARCHAR(100) NOT NULL,
    authorized_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    details JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
