'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { useAuth } from '@/lib/auth/context';
import { Skeleton } from '../ui/Skeleton';
import { Logo } from '@/components/branding/Logo';

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const pathname = usePathname();
  const { isLoading, isAuthenticated } = useAuth();

  // If we are on the /login page, render without the sidebar/topbar shell
  if (pathname === '/login') {
    return <main className="min-h-screen bg-background text-slate-100">{children}</main>;
  }

  if (isLoading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <Logo variant="full" size="lg" className="h-[50px] w-auto opacity-90" priority />
          <div className="flex items-center gap-2.5 mt-1">
            <div className="w-4 h-4 rounded border-2 border-blue-500 border-t-transparent animate-spin" />
            <span className="text-xs font-mono text-slate-400">Verifying session authority...</span>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null; // Will redirect via AuthProvider effect
  }

  return (
    <div className="flex h-screen bg-background text-slate-100 overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 bg-surface-400/30">{children}</main>
      </div>
    </div>
  );
};
