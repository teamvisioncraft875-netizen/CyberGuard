-- ======================================================================================
-- CYBERGUARD: Migration 011 — Add 'scheduled' to response_actions status constraint
-- ======================================================================================

ALTER TABLE public.response_actions 
  DROP CONSTRAINT IF EXISTS response_actions_status_check;

ALTER TABLE public.response_actions 
  ADD CONSTRAINT response_actions_status_check 
  CHECK (status IN (
    'proposed',
    'pending_approval',
    'approved',
    'scheduled',
    'rejected',
    'executed',
    'failed',
    'expired',
    'rolled_back'
  ));
