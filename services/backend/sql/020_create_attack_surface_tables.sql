-- ======================================================================================
-- CYBERGUARD Migration 020: Create Device Listening Ports Table (Phase A ASD)
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.device_listening_ports (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  device_id           UUID NOT NULL REFERENCES public.devices(id) ON DELETE CASCADE,
  port                INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
  protocol            VARCHAR(10) NOT NULL CHECK (protocol IN ('tcp', 'udp')),
  bind_address        TEXT NOT NULL,
  exposure_scope      VARCHAR(20) NOT NULL CHECK (exposure_scope IN ('loopback', 'private', 'public', 'unknown')),
  pid                 INTEGER NULL,
  process_name        VARCHAR(255) NULL,
  process_path        TEXT NULL,
  status              VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at           TIMESTAMPTZ NULL,
  CONSTRAINT uq_device_listening_port_status UNIQUE (device_id, port, protocol, bind_address, status)
);

-- Indexes for fast lookup and multi-tenant queries
CREATE INDEX IF NOT EXISTS idx_device_listening_ports_org 
  ON public.device_listening_ports (organization_id);

CREATE INDEX IF NOT EXISTS idx_device_listening_ports_device 
  ON public.device_listening_ports (device_id);

CREATE INDEX IF NOT EXISTS idx_device_listening_ports_status 
  ON public.device_listening_ports (status);

CREATE INDEX IF NOT EXISTS idx_device_listening_ports_port 
  ON public.device_listening_ports (port);

CREATE INDEX IF NOT EXISTS idx_device_listening_ports_exposure 
  ON public.device_listening_ports (exposure_scope);

CREATE INDEX IF NOT EXISTS idx_device_listening_ports_org_device_status
  ON public.device_listening_ports (organization_id, device_id, status);

COMMENT ON TABLE public.device_listening_ports IS 
  'Catalog of active and historical listening sockets discovered on enterprise devices (Attack Surface Discovery Phase A)';
