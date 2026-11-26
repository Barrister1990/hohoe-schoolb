'use client';

import LoadingOverlay from '@/components/shared/LoadingOverlay';
import { useAuthStore } from '@/lib/stores/auth-store';
import { UserRole } from '@/types';
import { useEffect } from 'react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: UserRole[];
  redirectTo?: string;
}

function dashboardForRole(role: string): string {
  return role === 'admin' ? '/admin/dashboard' : '/teacher/dashboard';
}

function hasRoleAccess(user: {
  role: string;
  isClassTeacher?: boolean;
  isSubjectTeacher?: boolean;
}, allowedRoles: UserRole[]): boolean {
  return allowedRoles.some((role) => {
    if (role === 'admin') return user.role === 'admin';
    if (role === 'class_teacher') return user.isClassTeacher === true;
    if (role === 'subject_teacher') return user.isSubjectTeacher === true;
    return false;
  });
}

export default function ProtectedRoute({
  children,
  allowedRoles,
  redirectTo = '/',
}: ProtectedRouteProps) {
  const { isAuthenticated, user, isLoading } = useAuthStore();

  useEffect(() => {
    if (isLoading) return;

    if (!isAuthenticated || !user) {
      window.location.href = redirectTo;
      return;
    }

    if (allowedRoles && allowedRoles.length > 0 && !hasRoleAccess(user, allowedRoles)) {
      window.location.href = dashboardForRole(user.role);
    }
  }, [isAuthenticated, user, isLoading, allowedRoles, redirectTo]);

  if (isLoading) {
    return <LoadingOverlay isLoading={true} message="Verifying authentication..." />;
  }

  if (!isAuthenticated || !user) {
    return <LoadingOverlay isLoading={true} message="Redirecting..." />;
  }

  if (allowedRoles && allowedRoles.length > 0 && !hasRoleAccess(user, allowedRoles)) {
    return <LoadingOverlay isLoading={true} message="Redirecting to your dashboard..." />;
  }

  return <>{children}</>;
}
