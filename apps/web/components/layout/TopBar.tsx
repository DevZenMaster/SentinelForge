'use client';

import React from 'react';
import Link from 'next/link';
import { useAuth } from '@/lib/auth/context';
import { LogOut, User as UserIcon } from 'lucide-react';
import { Button } from '../ui/Button';
import { Logo } from '@/components/branding/Logo';

export const TopBar: React.FC = () => {
  const { user, logout, isLoading } = useAuth();

  return (
    <header className="h-14 bg-surface-300 border-b border-slate-800 px-6 flex items-center justify-between flex-shrink-0">
      <div className="flex items-center gap-3">
        <div className="md:hidden flex items-center">
          <Logo variant="mark" size="sm" className="h-8 w-8 mr-1.5" href="/dashboard" />
        </div>
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-950/60 text-emerald-400 border border-emerald-800/80">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          SYSTEM OPERATIONAL
        </span>
      </div>

      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-3">
            <Link
              href="/settings"
              className="flex items-center gap-2 px-3 py-1 rounded bg-surface-200 hover:bg-surface-100 border border-slate-800 text-xs transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500"
              title="Manage User Settings & Profile"
            >
              <UserIcon className="w-3.5 h-3.5 text-slate-400" />
              <span className="font-mono text-slate-200">{user.username}</span>
              {user.is_superuser && (
                <span className="px-1.5 py-0.2 bg-red-950/80 text-red-400 border border-red-800 text-[10px] rounded font-mono uppercase">
                  ROOT
                </span>
              )}
            </Link>
            <Button
              variant="ghost"
              size="sm"
              onClick={logout}
              isLoading={isLoading}
              className="text-slate-400 hover:text-red-300 gap-1.5"
              title="Sign Out of Session"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Logout</span>
            </Button>
          </div>
        )}
      </div>
    </header>
  );
};
