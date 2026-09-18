'use client';

import React, { useState } from 'react';
import { useAuth } from '@/lib/auth/context';
import { Lock, User as UserIcon } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Logo } from '@/components/branding/Logo';

export default function LoginPage() {
  const { login } = useAuth();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier.trim() || !password) {
      setError('Please enter your username/email and password.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      await login({
        username_or_email: identifier.trim(),
        password,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Invalid credentials. Please verify your username and password.';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex flex-col items-center justify-center p-4 bg-background">
      <div className="w-full max-w-md bg-surface-200 border border-slate-800 rounded-lg shadow-2xl p-8">
        {/* Brand */}
        <div className="flex flex-col items-center text-center mb-8">
          <Logo variant="full" size="xl" className="h-[72px] w-auto mb-3" priority />
          <h1 className="sr-only">SentinelForge</h1>
          <p className="text-xs font-mono text-slate-400 uppercase tracking-widest mt-1">
            Security Operations Center Portal
          </p>
        </div>

        {error && (
          <div
            role="alert"
            className="mb-6 p-3 rounded bg-red-950/60 border border-red-800/80 text-xs text-red-300 font-mono"
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="identifier"
              className="block text-xs font-mono text-slate-400 mb-1.5 uppercase tracking-wider"
            >
              Username or Email
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <UserIcon className="w-4 h-4" />
              </div>
              <input
                id="identifier"
                type="text"
                required
                autoComplete="username"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                placeholder="analyst@sentinelforge.local"
                className="w-full pl-9 pr-3 py-2 bg-surface-300 border border-slate-700/80 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono transition-colors"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-xs font-mono text-slate-400 mb-1.5 uppercase tracking-wider"
            >
              Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                id="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 bg-surface-300 border border-slate-700/80 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono transition-colors"
              />
            </div>
          </div>

          <div className="pt-2">
            <Button
              type="submit"
              variant="primary"
              className="w-full py-2 text-xs font-mono tracking-wider uppercase"
              isLoading={isLoading}
            >
              Authenticate Session
            </Button>
          </div>
        </form>

        <div className="mt-8 pt-4 border-t border-slate-800 text-center text-[11px] font-mono text-slate-500">
          AUTHORIZED PERSONNEL ONLY • ALL ACCESS AUDITED
        </div>
      </div>
    </div>
  );
}
