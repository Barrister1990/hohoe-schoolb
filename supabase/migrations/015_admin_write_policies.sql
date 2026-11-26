-- ============================================
-- Admin write policies for academic tables
-- Fixes 403/500 on create/update/delete (e.g. POST /api/subjects)
-- Tables previously only had SELECT policies
-- ============================================

-- Ensure grants exist
GRANT SELECT, INSERT, UPDATE, DELETE ON public.classes TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.students TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.subjects TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.subject_assignments TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.grades TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.attendance TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.class_teacher_evaluations TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.class_teacher_rewards TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.grading_system TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.grade_levels TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.bece_results TO authenticated;

-- Helper: drop + recreate admin write policy on a table
-- Subjects
DROP POLICY IF EXISTS "Admins can manage subjects" ON public.subjects;
CREATE POLICY "Admins can manage subjects" ON public.subjects
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- Classes
DROP POLICY IF EXISTS "Admins can manage classes" ON public.classes;
CREATE POLICY "Admins can manage classes" ON public.classes
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- Students
DROP POLICY IF EXISTS "Admins can manage students" ON public.students;
CREATE POLICY "Admins can manage students" ON public.students
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- Subject assignments
DROP POLICY IF EXISTS "Admins can manage subject_assignments" ON public.subject_assignments;
CREATE POLICY "Admins can manage subject_assignments" ON public.subject_assignments
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- Grades (admins + teachers who need to write — admins for now; teachers later)
DROP POLICY IF EXISTS "Admins can manage grades" ON public.grades;
CREATE POLICY "Admins can manage grades" ON public.grades
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS "Authenticated users can write grades" ON public.grades;
CREATE POLICY "Authenticated users can write grades" ON public.grades
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Authenticated users can update grades" ON public.grades;
CREATE POLICY "Authenticated users can update grades" ON public.grades
  FOR UPDATE
  TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Authenticated users can delete grades" ON public.grades;
CREATE POLICY "Authenticated users can delete grades" ON public.grades
  FOR DELETE
  TO authenticated
  USING (auth.role() = 'authenticated');

-- Attendance
DROP POLICY IF EXISTS "Admins can manage attendance" ON public.attendance;
CREATE POLICY "Admins can manage attendance" ON public.attendance
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS "Authenticated users can write attendance" ON public.attendance;
CREATE POLICY "Authenticated users can write attendance" ON public.attendance
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Authenticated users can update attendance" ON public.attendance;
CREATE POLICY "Authenticated users can update attendance" ON public.attendance
  FOR UPDATE
  TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Authenticated users can delete attendance" ON public.attendance;
CREATE POLICY "Authenticated users can delete attendance" ON public.attendance
  FOR DELETE
  TO authenticated
  USING (auth.role() = 'authenticated');

-- Class teacher evaluations
DROP POLICY IF EXISTS "Admins can manage class_teacher_evaluations" ON public.class_teacher_evaluations;
CREATE POLICY "Admins can manage class_teacher_evaluations" ON public.class_teacher_evaluations
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS "Authenticated users can write class_teacher_evaluations" ON public.class_teacher_evaluations;
CREATE POLICY "Authenticated users can write class_teacher_evaluations" ON public.class_teacher_evaluations
  FOR ALL
  TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

-- Class teacher rewards
DROP POLICY IF EXISTS "Admins can manage class_teacher_rewards" ON public.class_teacher_rewards;
CREATE POLICY "Admins can manage class_teacher_rewards" ON public.class_teacher_rewards
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS "Authenticated users can write class_teacher_rewards" ON public.class_teacher_rewards;
CREATE POLICY "Authenticated users can write class_teacher_rewards" ON public.class_teacher_rewards
  FOR ALL
  TO authenticated
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

-- Grading system / grade levels / BECE (admin only writes)
DROP POLICY IF EXISTS "Admins can manage grading_system" ON public.grading_system;
CREATE POLICY "Admins can manage grading_system" ON public.grading_system
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS "Admins can manage grade_levels" ON public.grade_levels;
CREATE POLICY "Admins can manage grade_levels" ON public.grade_levels
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS "Admins can manage bece_results" ON public.bece_results;
CREATE POLICY "Admins can manage bece_results" ON public.bece_results
  FOR ALL
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());
