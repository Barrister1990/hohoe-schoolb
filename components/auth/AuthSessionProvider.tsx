'use client';

import { authService } from '@/lib/services/auth-service';
import { useAuthStore } from '@/lib/stores/auth-store';
import { supabase } from '@/lib/supabase/client';
import { useEffect, useRef } from 'react';

/**
 * Initializes and maintains Supabase auth session across page loads.
 * Never clears an already-authenticated user on timeout/errors.
 */
export function AuthSessionProvider({ children }: { children: React.ReactNode }) {
  const { setUser, setLoading } = useAuthStore();
  const initializingRef = useRef(false);

  useEffect(() => {
    let mounted = true;

    const withTimeout = <T,>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> => {
      return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`${label} timed out after ${timeoutMs}ms`));
        }, timeoutMs);

        promise
          .then((value) => {
            clearTimeout(timer);
            resolve(value);
          })
          .catch((err) => {
            clearTimeout(timer);
            reject(err);
          });
      });
    };

    const initSession = async () => {
      if (initializingRef.current) return;
      initializingRef.current = true;

      try {
        setLoading(true);

        const { data: { session } } = await withTimeout(
          supabase.auth.getSession(),
          5000,
          'getSession'
        );

        if (!mounted) return;

        if (!session) {
          // Only clear if we don't already have a user from a concurrent login()
          const existing = useAuthStore.getState().user;
          if (!existing) {
            setUser(null);
          }
          return;
        }

        // Prefer existing user set by login() — avoid duplicate fetch races
        const existing = useAuthStore.getState().user;
        if (existing) {
          return;
        }

        try {
          const user = await withTimeout(authService.getCurrentUser(), 5000, 'getCurrentUser');
          if (mounted && user) {
            setUser(user);
          } else if (mounted && !useAuthStore.getState().user) {
            // Session exists but profile failed — keep loading false; don't blank forever
            console.warn('Session found but user profile could not be loaded');
          }
        } catch (profileError) {
          console.warn('Profile fetch failed during init (non-fatal):', profileError);
          // Do NOT setUser(null) here — session may still be valid / login may have set user
        }
      } catch (error) {
        console.warn('Error initializing session (non-fatal):', error);
        // Do NOT wipe user on timeout — that caused the blank dashboard
      } finally {
        if (mounted) {
          setLoading(false);
        }
        initializingRef.current = false;
      }
    };

    initSession();

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(async (event, session) => {
      if (!mounted) return;

      if (event === 'SIGNED_IN' && session) {
        const storeState = useAuthStore.getState();
        if (storeState.user) {
          // login() already populated the store — don't race another fetch
          setLoading(false);
          return;
        }

        try {
          const user = await withTimeout(authService.getCurrentUser(), 5000, 'getCurrentUser');
          if (user && mounted) {
            setUser(user);
          }
        } catch (error) {
          console.warn('SIGNED_IN profile fetch failed (non-fatal):', error);
        } finally {
          if (mounted) setLoading(false);
        }
      } else if (event === 'SIGNED_OUT') {
        setUser(null);
        setLoading(false);
      } else if (event === 'TOKEN_REFRESHED' && session) {
        // Background refresh only — never block UI or clear user on failure
        try {
          const user = await withTimeout(authService.getCurrentUser(), 5000, 'getCurrentUser');
          if (user && mounted) {
            setUser(user);
          }
        } catch {
          // ignore
        }
      }
    });

    const safetyTimeout = setTimeout(() => {
      if (mounted) {
        setLoading(false);
      }
    }, 8000);

    return () => {
      mounted = false;
      subscription.unsubscribe();
      clearTimeout(safetyTimeout);
    };
  }, [setUser, setLoading]);

  return <>{children}</>;
}
