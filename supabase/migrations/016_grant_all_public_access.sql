-- ============================================
-- COMPREHENSIVE FIX: grants + RLS for ALL tables
-- Stops 42501 "permission denied for table X" across the app
-- Run this once in Supabase SQL Editor
-- ============================================

-- 0) Ensure helper functions exist (safe to re-run)
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

CREATE OR REPLACE FUNCTION public.get_my_profile()
RETURNS SETOF public.users
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
  SELECT * FROM public.users WHERE auth_user_id = auth.uid() LIMIT 1;
$$;

ALTER FUNCTION public.get_my_profile() OWNER TO postgres;
GRANT EXECUTE ON FUNCTION public.get_my_profile() TO authenticated, anon;

-- 1) Schema usage
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

-- 2) Grant on EVERY existing table/sequence/function in public
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated, service_role;

-- 3) Default privileges so FUTURE tables/functions also get grants automatically
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON TABLES TO anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;

-- 4) Ensure RLS is on for all app tables
DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users','admins','classes','students','subjects','subject_assignments',
    'grades','attendance','class_teacher_evaluations','class_teacher_rewards',
    'grading_system','grade_levels','bece_results',
    'school_settings','academic_settings','assessment_structure',
    'user_preferences','system_preferences','term_settings',
    'permissions','user_permissions'
  ]
  LOOP
    IF EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = t
    ) THEN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    END IF;
  END LOOP;
END $$;

-- 5) Authenticated READ on all operational tables (idempotent)
DO $$
DECLARE
  t TEXT;
  pol TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'classes','students','subjects','subject_assignments',
    'grades','attendance','class_teacher_evaluations','class_teacher_rewards',
    'grading_system','grade_levels','bece_results',
    'school_settings','academic_settings','assessment_structure',
    'system_preferences','term_settings','permissions'
  ]
  LOOP
    IF EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = t
    ) THEN
      pol := format('Authenticated users can read %s', t);
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', pol, t);
      EXECUTE format(
        'CREATE POLICY %I ON public.%I FOR SELECT TO authenticated USING (auth.role() = ''authenticated'')',
        pol, t
      );
    END IF;
  END LOOP;
END $$;

-- 6) Admin FULL access on all operational tables
DO $$
DECLARE
  t TEXT;
  pol TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'classes','students','subjects','subject_assignments',
    'grades','attendance','class_teacher_evaluations','class_teacher_rewards',
    'grading_system','grade_levels','bece_results',
    'school_settings','academic_settings','assessment_structure',
    'system_preferences','term_settings','permissions','user_permissions',
    'admins'
  ]
  LOOP
    IF EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = t
    ) THEN
      pol := format('Admins can manage %s', t);
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', pol, t);
      EXECUTE format(
        'CREATE POLICY %I ON public.%I FOR ALL TO authenticated USING (public.is_admin()) WITH CHECK (public.is_admin())',
        pol, t
      );
    END IF;
  END LOOP;
END $$;

-- 7) Teachers / authenticated write on day-to-day tables
DROP POLICY IF EXISTS "Authenticated users can write grades" ON public.grades;
CREATE POLICY "Authenticated users can write grades" ON public.grades
  FOR INSERT TO authenticated WITH CHECK (auth.role() = 'authenticated');
DROP POLICY IF EXISTS "Authenticated users can update grades" ON public.grades;
CREATE POLICY "Authenticated users can update grades" ON public.grades
  FOR UPDATE TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');
DROP POLICY IF EXISTS "Authenticated users can delete grades" ON public.grades;
CREATE POLICY "Authenticated users can delete grades" ON public.grades
  FOR DELETE TO authenticated USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Authenticated users can write attendance" ON public.attendance;
CREATE POLICY "Authenticated users can write attendance" ON public.attendance
  FOR INSERT TO authenticated WITH CHECK (auth.role() = 'authenticated');
DROP POLICY IF EXISTS "Authenticated users can update attendance" ON public.attendance;
CREATE POLICY "Authenticated users can update attendance" ON public.attendance
  FOR UPDATE TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');
DROP POLICY IF EXISTS "Authenticated users can delete attendance" ON public.attendance;
CREATE POLICY "Authenticated users can delete attendance" ON public.attendance
  FOR DELETE TO authenticated USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Authenticated users can write class_teacher_evaluations" ON public.class_teacher_evaluations;
CREATE POLICY "Authenticated users can write class_teacher_evaluations" ON public.class_teacher_evaluations
  FOR ALL TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Authenticated users can write class_teacher_rewards" ON public.class_teacher_rewards;
CREATE POLICY "Authenticated users can write class_teacher_rewards" ON public.class_teacher_rewards
  FOR ALL TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Authenticated users can write subject_assignments" ON public.subject_assignments;
CREATE POLICY "Authenticated users can write subject_assignments" ON public.subject_assignments
  FOR ALL TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

-- Teachers can add/update students (teacher/students/new)
DROP POLICY IF EXISTS "Authenticated users can write students" ON public.students;
CREATE POLICY "Authenticated users can write students" ON public.students
  FOR INSERT TO authenticated
  WITH CHECK (auth.role() = 'authenticated');
DROP POLICY IF EXISTS "Authenticated users can update students" ON public.students;
CREATE POLICY "Authenticated users can update students" ON public.students
  FOR UPDATE TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

-- 8) user_permissions: own read + admin manage (already covered above)
DROP POLICY IF EXISTS "Users can view own permissions" ON public.user_permissions;
CREATE POLICY "Users can view own permissions" ON public.user_permissions
  FOR SELECT TO authenticated
  USING (user_id IN (SELECT id FROM public.users WHERE auth_user_id = auth.uid()));

-- 9) user_preferences: own CRUD
DROP POLICY IF EXISTS "Users can view own preferences" ON public.user_preferences;
CREATE POLICY "Users can view own preferences" ON public.user_preferences
  FOR SELECT TO authenticated
  USING (user_id IN (SELECT id FROM public.users WHERE auth_user_id = auth.uid()));

DROP POLICY IF EXISTS "Users can update own preferences" ON public.user_preferences;
CREATE POLICY "Users can update own preferences" ON public.user_preferences
  FOR UPDATE TO authenticated
  USING (user_id IN (SELECT id FROM public.users WHERE auth_user_id = auth.uid()))
  WITH CHECK (user_id IN (SELECT id FROM public.users WHERE auth_user_id = auth.uid()));

DROP POLICY IF EXISTS "Users can insert own preferences" ON public.user_preferences;
CREATE POLICY "Users can insert own preferences" ON public.user_preferences
  FOR INSERT TO authenticated
  WITH CHECK (user_id IN (SELECT id FROM public.users WHERE auth_user_id = auth.uid()));

DROP POLICY IF EXISTS "Admins can manage user_preferences" ON public.user_preferences;
CREATE POLICY "Admins can manage user_preferences" ON public.user_preferences
  FOR ALL TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- 10) users table: own SELECT + admin manage (keep login working)
DROP POLICY IF EXISTS "Users can view own profile" ON public.users;
CREATE POLICY "Users can view own profile" ON public.users
  FOR SELECT TO authenticated
  USING (auth_user_id = auth.uid());

DROP POLICY IF EXISTS "Users can view own profile by email" ON public.users;
CREATE POLICY "Users can view own profile by email" ON public.users
  FOR SELECT TO authenticated
  USING (email = (auth.jwt() ->> 'email'));

DROP POLICY IF EXISTS "Admins can view all users" ON public.users;
CREATE POLICY "Admins can view all users" ON public.users
  FOR SELECT TO authenticated
  USING (public.is_admin());

DROP POLICY IF EXISTS "Admins can insert users" ON public.users;
CREATE POLICY "Admins can insert users" ON public.users
  FOR INSERT TO authenticated
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS "Admins can update users" ON public.users;
CREATE POLICY "Admins can update users" ON public.users
  FOR UPDATE TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS "Admins can delete users" ON public.users;
CREATE POLICY "Admins can delete users" ON public.users
  FOR DELETE TO authenticated
  USING (public.is_admin());
