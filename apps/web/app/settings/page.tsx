'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  User,
  Shield,
  KeyRound,
  Lock,
  CheckCircle2,
  AlertCircle,
  Clock,
  ShieldCheck,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '@/lib/auth/context';
import { usersApi } from '@/lib/api/users';
import { UserDetail } from '@/types/users';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Skeleton';
import { formatDate } from '@/lib/utils';

export default function UserSettingsPage() {
  const { refresh: refreshAuthContext } = useAuth();
  const [profile, setProfile] = useState<UserDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Profile form state
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileSuccess, setProfileSuccess] = useState<string | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);

  // Password form state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);

  const fetchProfile = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await usersApi.getMyProfile();
      setProfile(data);
      setFullName(data.full_name || '');
      setUsername(data.username);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load user profile.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProfile();
  }, [fetchProfile]);

  const handleProfileSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfileSaving(true);
    setProfileSuccess(null);
    setProfileError(null);

    const trimmedUsername = username.trim();
    if (trimmedUsername.length < 3) {
      setProfileError('Username must be at least 3 characters.');
      setProfileSaving(false);
      return;
    }

    try {
      const updated = await usersApi.updateMyProfile({
        full_name: fullName.trim() || null,
        username: trimmedUsername,
      });
      setProfile(updated);
      setFullName(updated.full_name || '');
      setUsername(updated.username);
      setProfileSuccess('Profile successfully updated.');
      await refreshAuthContext();
    } catch (err: unknown) {
      setProfileError(err instanceof Error ? err.message : 'Failed to update profile.');
    } finally {
      setProfileSaving(false);
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordSaving(true);
    setPasswordSuccess(null);
    setPasswordError(null);

    if (!currentPassword) {
      setPasswordError('Current password is required.');
      setPasswordSaving(false);
      return;
    }

    if (newPassword.length < 12) {
      setPasswordError('New password must be at least 12 characters in length.');
      setPasswordSaving(false);
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordError('New password and confirmation do not match.');
      setPasswordSaving(false);
      return;
    }

    if (newPassword === currentPassword) {
      setPasswordError('New password cannot be the same as current password.');
      setPasswordSaving(false);
      return;
    }

    try {
      const resp = await usersApi.changeMyPassword({
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });
      setPasswordSuccess(resp.message || 'Password successfully updated.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: unknown) {
      setPasswordError(err instanceof Error ? err.message : 'Failed to update password.');
    } finally {
      setPasswordSaving(false);
    }
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6 max-w-5xl mx-auto">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Skeleton className="h-96 w-full" />
          <Skeleton className="h-96 w-full" />
        </div>
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="p-6 max-w-2xl mx-auto">
        <div className="p-4 rounded border border-red-800/80 bg-red-950/30 text-red-400 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <div>
            <h3 className="font-semibold text-sm">Failed to Load Profile</h3>
            <p className="text-xs text-red-300 mt-0.5">{error || 'Unknown error occurred.'}</p>
          </div>
          <Button variant="outline" size="sm" onClick={fetchProfile} className="ml-auto">
            Retry
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6 select-none">
      {/* Page Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <User className="w-5 h-5 text-blue-400" />
            User Settings & Profile
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage your personal profile, credentials, and inspect security telemetry.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={fetchProfile} className="gap-1.5 text-xs">
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Account Profile & Password */}
        <div className="lg:col-span-7 space-y-6">
          {/* Account Profile Card */}
          <Card className="p-5 border-slate-800 bg-surface-300">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
              <User className="w-4 h-4 text-blue-400" />
              Profile Details
            </h2>

            {profileSuccess && (
              <div className="mb-4 p-3 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
                <span>{profileSuccess}</span>
              </div>
            )}

            {profileError && (
              <div className="mb-4 p-3 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-400" />
                <span>{profileError}</span>
              </div>
            )}

            <form onSubmit={handleProfileSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Display Name
                </label>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. John Doe"
                  className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-sans"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Username <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  pattern="^[a-zA-Z0-9_\-\.]{3,64}$"
                  title="3-64 characters, letters, numbers, underscores, dashes, or periods"
                  className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Alphanumeric characters, underscores, dashes, or periods (3-64 chars).
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <input
                    type="email"
                    value={profile.email}
                    disabled
                    className="w-full px-3 py-2 text-xs rounded bg-surface-500 border border-slate-800 text-slate-400 cursor-not-allowed font-mono pr-8"
                  />
                  <Lock className="w-3.5 h-3.5 text-slate-500 absolute right-2.5 top-2.5" />
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Email is managed by administrators and cannot be altered via self-service.
                </p>
              </div>

              <div className="pt-2 flex justify-end">
                <Button type="submit" variant="primary" size="sm" isLoading={profileSaving}>
                  Save Profile Changes
                </Button>
              </div>
            </form>
          </Card>

          {/* Security & Password Card */}
          <Card className="p-5 border-slate-800 bg-surface-300">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
              <KeyRound className="w-4 h-4 text-amber-400" />
              Change Password
            </h2>

            <div className="mb-4 p-3 rounded bg-blue-950/40 border border-blue-800/60 text-blue-300 text-xs flex items-start gap-2.5">
              <Shield className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p className="font-semibold text-blue-200">Security Policy:</p>
                <p className="text-slate-300">
                  Password must be at least 12 characters. Changing your password updates your
                  Argon2id cryptographic hash and invalidates all other active sessions across other
                  devices.
                </p>
              </div>
            </div>

            {passwordSuccess && (
              <div className="mb-4 p-3 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
                <span>{passwordSuccess}</span>
              </div>
            )}

            {passwordError && (
              <div className="mb-4 p-3 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-400" />
                <span>{passwordError}</span>
              </div>
            )}

            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Current Password <span className="text-red-400">*</span>
                </label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  required
                  placeholder="••••••••••••"
                  className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    New Password <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    minLength={12}
                    placeholder="Min 12 characters"
                    className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Confirm New Password <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                    minLength={12}
                    placeholder="Repeat new password"
                    className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <Button type="submit" variant="danger" size="sm" isLoading={passwordSaving}>
                  Update Password
                </Button>
              </div>
            </form>
          </Card>
        </div>

        {/* Right Column: Roles, Permissions & Telemetry */}
        <div className="lg:col-span-5 space-y-6">
          {/* Identity & Role Overview */}
          <Card className="p-5 border-slate-800 bg-surface-300">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Roles & Authorization
            </h2>

            <div className="space-y-4">
              <div>
                <span className="text-xs font-medium text-slate-400 block mb-2">
                  Assigned Roles
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {profile.roles.length > 0 ? (
                    profile.roles.map((r) => (
                      <Badge
                        key={r}
                        variant={r === 'ADMIN' ? 'danger' : r === 'ANALYST' ? 'primary' : 'outline'}
                        className="font-mono text-[11px] uppercase tracking-wider"
                      >
                        {r}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500">No roles assigned</span>
                  )}
                  {profile.is_superuser && (
                    <Badge variant="danger" className="font-mono text-[11px] uppercase">
                      SUPERUSER
                    </Badge>
                  )}
                </div>
              </div>

              <div>
                <span className="text-xs font-medium text-slate-400 block mb-2">
                  Derived Capabilities ({profile.permissions.length})
                </span>
                <div className="max-h-48 overflow-y-auto pr-1 space-y-1 rounded bg-surface-400/50 p-2 border border-slate-800 font-mono text-[11px]">
                  {profile.permissions.map((p) => (
                    <div
                      key={p}
                      className="px-2 py-0.5 rounded bg-surface-300 text-slate-300 flex items-center justify-between"
                    >
                      <span>{p}</span>
                      <span className="text-emerald-400 text-[10px]">ALLOWED</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Card>

          {/* Account Telemetry & Security Card */}
          <Card className="p-5 border-slate-800 bg-surface-300">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
              <Clock className="w-4 h-4 text-cyan-400" />
              Account Metadata & Security
            </h2>

            <div className="space-y-3 text-xs font-mono">
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Account ID:</span>
                <span className="text-slate-300 truncate max-w-[200px]" title={profile.id}>
                  {profile.id}
                </span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Status:</span>
                <span className="text-emerald-400 font-semibold">
                  {profile.is_active ? 'ACTIVE' : 'DEACTIVATED'}
                </span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Created:</span>
                <span className="text-slate-300">{formatDate(profile.created_at)}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Last Profile Update:</span>
                <span className="text-slate-300">{formatDate(profile.updated_at)}</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-slate-400">Last Authentication:</span>
                <span className="text-slate-300">
                  {profile.last_login_at ? formatDate(profile.last_login_at) : 'Current Session'}
                </span>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
