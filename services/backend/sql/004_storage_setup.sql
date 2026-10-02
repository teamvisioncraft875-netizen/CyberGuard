-- CYBERGUARD: Supabase Storage Configuration & RLS Policies
-- Bucket: cyberguard-media
-- Limits: 50MB (52,428,800 bytes) max file size

-- 1. Create storage bucket if not exists
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'cyberguard-media',
  'cyberguard-media',
  false,
  52428800,
  ARRAY['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'audio/wav', 'audio/mpeg', 'audio/ogg', 'audio/mp4', 'audio/x-m4a']
)
ON CONFLICT (id) DO UPDATE SET
  public = false,
  file_size_limit = 52428800;

-- 2. Storage RLS Policies on storage.objects

-- Allow authenticated users to upload only to their own /uploads/<user_id>/* directory
DROP POLICY IF EXISTS "Allow authenticated users to upload own media" ON storage.objects;
CREATE POLICY "Allow authenticated users to upload own media"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'cyberguard-media'
  AND (
    name LIKE 'uploads/' || auth.uid()::text || '/%'
    OR name LIKE '/uploads/' || auth.uid()::text || '/%'
  )
);

-- Allow authenticated users to read only from their own /uploads/<user_id>/* directory
DROP POLICY IF EXISTS "Allow authenticated users to read own media" ON storage.objects;
CREATE POLICY "Allow authenticated users to read own media"
ON storage.objects
FOR SELECT
TO authenticated
USING (
  bucket_id = 'cyberguard-media'
  AND (
    name LIKE 'uploads/' || auth.uid()::text || '/%'
    OR name LIKE '/uploads/' || auth.uid()::text || '/%'
  )
);

-- Allow backend service role full access across all paths (to forward media to FastAPI engines)
DROP POLICY IF EXISTS "Allow service role full access to cyberguard-media" ON storage.objects;
CREATE POLICY "Allow service role full access to cyberguard-media"
ON storage.objects
FOR ALL
TO service_role
USING (bucket_id = 'cyberguard-media')
WITH CHECK (bucket_id = 'cyberguard-media');
