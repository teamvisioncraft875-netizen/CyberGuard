-- ======================================================================================
-- CYBERGUARD Migration 009: Add exposed_secret to threat_type & check to source_type
-- ======================================================================================

ALTER TYPE threat_type ADD VALUE IF NOT EXISTS 'exposed_secret';
ALTER TYPE source_type ADD VALUE IF NOT EXISTS 'check';
ALTER TYPE source_type ADD VALUE IF NOT EXISTS 'telemetry';
