-- ════════════════════════════════════════════════════════════
--  AccountSync — Users Table Setup
--  Run this ONCE in your Supabase SQL Editor
--  https://supabase.com/dashboard/project/lqhyqkhlwlsxoazousif/sql
-- ════════════════════════════════════════════════════════════

-- 1. Create the users table
CREATE TABLE IF NOT EXISTS public.accountsync_users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,        -- bcrypt hash, NEVER plain text
    full_name     text DEFAULT '',
    is_active     boolean NOT NULL DEFAULT true,  -- set FALSE to revoke access
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login    timestamptz
);

-- 2. Enable Row Level Security
ALTER TABLE public.accountsync_users ENABLE ROW LEVEL SECURITY;

-- 3. RLS Policy — allow all (app uses anon key, logic handled in Python)
DROP POLICY IF EXISTS "allow_all_users" ON public.accountsync_users;
CREATE POLICY "allow_all_users" ON public.accountsync_users
    FOR ALL USING (true) WITH CHECK (true);

-- 4. Insert default admin user
--    Username : admin
--    Password : Admin@123
--    (Change this password after first login!)
INSERT INTO public.accountsync_users (username, password_hash, full_name, is_active)
VALUES (
    'admin',
    '$2b$12$gKrhLuK.6xHt6NJ8WBLL.O3nN3Khil0PgR/d4X1FGptaNTexZ4Hvy',
    'Administrator',
    true
)
ON CONFLICT (username) DO NOTHING;

-- 5. Insert temp user
--    Username : tempuser
--    Password : Temp@1234
--    (Delete this user when no longer needed)
INSERT INTO public.accountsync_users (username, password_hash, full_name, is_active)
VALUES (
    'tempuser',
    '$2b$12$r4TPRbNyl2nIf/2HX/0/5.QFpW8fMF/9pjTJCNnPcaHo70sA6Q2KG',
    'Temp User',
    true
)
ON CONFLICT (username) DO NOTHING;

-- ════════════════════════════════════════════════════════════
--  HOW TO ADD MORE USERS:
--  Replace MY_USERNAME, MY_FULL_NAME, and paste a new bcrypt
--  hash (generate at https://bcrypt-generator.com, rounds=12)
-- ════════════════════════════════════════════════════════════
-- INSERT INTO public.accountsync_users (username, password_hash, full_name, is_active)
-- VALUES ('MY_USERNAME', 'PASTE_BCRYPT_HASH_HERE', 'MY_FULL_NAME', true);

-- ════════════════════════════════════════════════════════════
--  HOW TO REVOKE ACCESS (user can no longer login):
--  UPDATE public.accountsync_users SET is_active = false
--  WHERE username = 'MY_USERNAME';
-- ════════════════════════════════════════════════════════════

-- ════════════════════════════════════════════════════════════
--  HOW TO DELETE A USER PERMANENTLY:
--  DELETE FROM public.accountsync_users WHERE username = 'MY_USERNAME';
-- ════════════════════════════════════════════════════════════
