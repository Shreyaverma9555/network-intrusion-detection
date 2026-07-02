-- Sentinel NID SOC schema for Supabase PostgreSQL.
-- Safe to run repeatedly from Supabase SQL Editor.

CREATE TABLE IF NOT EXISTS public.nid_users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst'
        CHECK (role IN ('admin', 'analyst', 'viewer')),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.nid_events (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip INET,
    destination_ip INET,
    category TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    confidence DOUBLE PRECISION NOT NULL
        CHECK (confidence >= 0 AND confidence <= 1),
    attack_probability DOUBLE PRECISION NOT NULL
        CHECK (attack_probability >= 0 AND attack_probability <= 1),
    threat_score DOUBLE PRECISION,
    packet_count INTEGER NOT NULL CHECK (packet_count > 0),
    predicted_attack BOOLEAN NOT NULL,
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS public.nid_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_nid_events_created_at
    ON public.nid_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_nid_events_source_ip
    ON public.nid_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_nid_events_category
    ON public.nid_events (category);
CREATE INDEX IF NOT EXISTS idx_nid_events_severity
    ON public.nid_events (severity);
CREATE INDEX IF NOT EXISTS idx_nid_events_attack
    ON public.nid_events (predicted_attack, created_at DESC);

COMMENT ON TABLE public.nid_events IS
    'Network detection events submitted by authenticated detector agents.';
COMMENT ON TABLE public.nid_audit_logs IS
    'SOC analyst, administration, and automated-response audit trail.';
