-- ======================================================================================
-- CYBERGUARD Migration 015: Add target_device_id to response_actions table
-- ======================================================================================

ALTER TABLE public.response_actions 
  ADD COLUMN IF NOT EXISTS target_device_id UUID NULL REFERENCES public.devices(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_response_actions_target_device_id 
  ON public.response_actions(target_device_id);

COMMENT ON COLUMN public.response_actions.target_device_id IS 'Target agent device UUID for endpoint containment actions (block_ip, isolate_device, suspend_device).';
