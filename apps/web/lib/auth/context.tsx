'use client';

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { User } from '@/types/auth';
import { apiClient } from '@/lib/api/client';

interface AuthContextType {
  user: User | null;
  roles: string[];
  permissions: string[];
  isLoading: boolean;
  isAuthenticated: boolean;
  hasRole: (role: string) => boolean;
  hasPermission: (permission: string) => boolean;
  hasAnyPermission: (permissions: string[]) => boolean;
  login: (credentials: { username_or_email: string; password: string }) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface UserProfileResponse extends User {
  roles: string[];
  permissions: string[];
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [roles, setRoles] = useState<string[]>([]);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const router = useRouter();
  const pathname = usePathname();

  const fetchUserProfile = useCallback(async () => {
    try {
      const data = await apiClient.get<UserProfileResponse>('/api/v1/auth/me');
      setUser({
        id: data.id,
        username: data.username,
        email: data.email,
        full_name: data.full_name,
        is_active: data.is_active,
        is_superuser: data.is_superuser,
      });
      setRoles(data.roles || []);
      setPermissions(data.permissions || []);
    } catch {
      setUser(null);
      setRoles([]);
      setPermissions([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUserProfile();
  }, [fetchUserProfile]);

  useEffect(() => {
    // Redirect unauthenticated users to /login if they attempt to access protected pages
    if (!isLoading && !user && pathname !== '/login') {
      router.push('/login');
    }
  }, [isLoading, user, pathname, router]);

  const login = async (credentials: { username_or_email: string; password: string }) => {
    setIsLoading(true);
    try {
      const data = await apiClient.post<UserProfileResponse>('/api/v1/auth/login', credentials);
      setUser({
        id: data.id,
        username: data.username,
        email: data.email,
        full_name: data.full_name,
        is_active: data.is_active,
        is_superuser: data.is_superuser,
      });
      setRoles(data.roles || []);
      setPermissions(data.permissions || []);
      router.push('/dashboard');
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      await apiClient.post('/api/v1/auth/logout');
    } catch {
      // Ignore errors on logout
    } finally {
      setUser(null);
      setRoles([]);
      setPermissions([]);
      setIsLoading(false);
      router.push('/login');
    }
  };

  const hasRole = useCallback(
    (role: string) => {
      if (user?.is_superuser) return true;
      return roles.some((r) => r.toUpperCase() === role.toUpperCase());
    },
    [user, roles]
  );

  const hasPermission = useCallback(
    (permission: string) => {
      if (user?.is_superuser) return true;
      return permissions.includes(permission);
    },
    [user, permissions]
  );

  const hasAnyPermission = useCallback(
    (targetPermissions: string[]) => {
      if (user?.is_superuser) return true;
      return targetPermissions.some((p) => permissions.includes(p));
    },
    [user, permissions]
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        roles,
        permissions,
        isLoading,
        isAuthenticated: !!user,
        hasRole,
        hasPermission,
        hasAnyPermission,
        login,
        logout,
        refresh: fetchUserProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
