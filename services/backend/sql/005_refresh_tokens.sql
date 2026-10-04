-- CYBERGUARD: Refresh Tokens Schema & Indexes
-- Table: public.refresh_tokens

CREATE TABLE IF NOT EXISTS public.refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

-- Index on (user_id, is_revoked) for fast active-token queries and revocation
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_revoked ON public.refresh_tokens(user_id, is_revoked);

-- Index on token_hash for rapid O(1) lookup during refresh requests
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON public.refresh_tokens(token_hash);

-- Index on expires_at for fast periodic cleanup
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON public.refresh_tokens(expires_at);
