-- ============================================
-- Fix 403 on public.users during login
-- Grants + clean SELECT policies + safe is_admin()
-- ============================================

-- 1) Ensure API roles can access the table (403 without this)
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO authenticated;
GRANT SELECT ON public.users TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.admins TO authenticated;

-- 2) Rebuild is_admin() so it never recurses through RLS
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.users
    WHERE auth_user_id = auth.uid()
    AND role = 'admin'
  );
$$;

ALTER FUNCTION public.is_admin() OWNER TO postgres;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated, anon;

-- 3) Drop every policy on users/admins so nothing conflicts
DO $$
DECLARE
  pol RECORD;
BEGIN
  FOR pol IN
    SELECT policyname, tablename
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename IN ('users', 'admins')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', pol.policyname, pol.tablename);
  END LOOP;
END $$;

-- 4) SELECT: any logged-in user can read their own row (required for login)
CREATE POLICY "Users can view own profile" ON public.users
  FOR SELECT
  TO authenticated
  USING (auth_user_id = auth.uid());

-- Also allow match by email as a fallback (covers older rows)
CREATE POLICY "Users can view own profile by email" ON public.users
  FOR SELECT
  TO authenticated
  USING (email = (auth.jwt() ->> 'email'));

-- 5) Admins can read/write all users
CREATE POLICY "Admins can view all users" ON public.users
  FOR SELECT
  TO authenticated
  USING (public.is_admin());

CREATE POLICY "Admins can insert users" ON public.users
  FOR INSERT
  TO authenticated
  WITH CHECK (public.is_admin());

CREATE POLICY "Admins can update users" ON public.users
  FOR UPDATE
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "Admins can delete users" ON public.users
  FOR DELETE
  TO authenticated
  USING (public.is_admin());

-- 6) Admins table
CREATE POLICY "Admins can access admins" ON public.admins
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());
