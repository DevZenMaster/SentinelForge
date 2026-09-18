'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  Users,
  UserPlus,
  Search,
  RefreshCw,
  Shield,
  ShieldAlert,
  UserCheck,
  UserX,
  Trash2,
  Edit2,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';
import { useAuth } from '@/lib/auth/context';
import { usersApi } from '@/lib/api/users';
import { RoleItem, UserAdminListItem, UserDetail } from '@/types/users';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Modal } from '@/components/ui/Modal';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Skeleton } from '@/components/ui/Skeleton';
import { formatDate } from '@/lib/utils';

export default function AdminUsersPage() {
  const { hasPermission, hasRole, user: currentUser } = useAuth();
  const canReadUsers = hasPermission('users.read') || hasRole('ADMIN');
  const canCreateUsers = hasPermission('users.create') || hasRole('ADMIN');
  const canUpdateUsers = hasPermission('users.update') || hasRole('ADMIN');
  const canDeleteUsers = hasPermission('users.delete') || hasRole('ADMIN');

  const [users, setUsers] = useState<UserAdminListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [roles, setRoles] = useState<RoleItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Search and filter states
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Create User Modal state
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [createUsername, setCreateUsername] = useState('');
  const [createEmail, setCreateEmail] = useState('');
  const [createFullName, setCreateFullName] = useState('');
  const [createPassword, setCreatePassword] = useState('');
  const [createRoles, setCreateRoles] = useState<string[]>(['ANALYST']);
  const [createActive, setCreateActive] = useState(true);
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Edit User Modal state
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [editUsername, setEditUsername] = useState('');
  const [editEmail, setEditEmail] = useState('');
  const [editFullName, setEditFullName] = useState('');
  const [editRoles, setEditRoles] = useState<string[]>([]);
  const [editActive, setEditActive] = useState(true);
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  // Deactivate/Activate ConfirmDialog state
  const [statusTarget, setStatusTarget] = useState<UserAdminListItem | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);

  // Delete ConfirmDialog state
  const [deleteTarget, setDeleteTarget] = useState<UserAdminListItem | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const fetchUsers = useCallback(async () => {
    if (!canReadUsers) return;
    setIsLoading(true);
    setActionError(null);
    try {
      const activeParam =
        statusFilter === 'active' ? true : statusFilter === 'deactivated' ? false : undefined;

      const data = await usersApi.listUsers({
        search: search.trim() || undefined,
        role: roleFilter || undefined,
        is_active: activeParam,
      });
      setUsers(data.items || []);
      setTotal(data.total || 0);
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : 'Failed to retrieve user accounts.');
    } finally {
      setIsLoading(false);
    }
  }, [canReadUsers, search, roleFilter, statusFilter]);

  const fetchRoles = useCallback(async () => {
    if (!canReadUsers) return;
    try {
      const data = await usersApi.listRoles();
      setRoles(data.items || []);
    } catch {
      // Fallback baseline roles if listRoles fails
      setRoles([
        { id: '1', name: 'ADMIN', description: 'Full system administration' },
        { id: '2', name: 'ANALYST', description: 'Security triage and investigation' },
        { id: '3', name: 'VIEWER', description: 'Read-only visibility' },
      ]);
    }
  }, [canReadUsers]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  useEffect(() => {
    fetchRoles();
  }, [fetchRoles]);

  // Handle User Creation
  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateLoading(true);
    setCreateError(null);

    try {
      await usersApi.createUser({
        username: createUsername.trim(),
        email: createEmail.trim(),
        full_name: createFullName.trim() || null,
        password: createPassword,
        roles: createRoles,
        is_active: createActive,
      });

      setIsCreateOpen(false);
      setCreateUsername('');
      setCreateEmail('');
      setCreateFullName('');
      setCreatePassword('');
      setCreateRoles(['ANALYST']);
      setCreateActive(true);
      setActionSuccess(`User account created successfully.`);
      fetchUsers();
    } catch (err: unknown) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create user account.');
    } finally {
      setCreateLoading(false);
    }
  };

  // Open Edit Modal
  const openEditModal = async (user: UserAdminListItem) => {
    setEditingUserId(user.id);
    setEditUsername(user.username);
    setEditEmail(user.email);
    setEditFullName(user.full_name || '');
    setEditRoles(user.roles || []);
    setEditActive(user.is_active);
    setEditError(null);
    setIsEditOpen(true);
  };

  // Handle User Update
  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUserId) return;

    setEditLoading(true);
    setEditError(null);

    try {
      await usersApi.updateUser(editingUserId, {
        username: editUsername.trim() || undefined,
        email: editEmail.trim() || undefined,
        full_name: editFullName.trim() || null,
        roles: editRoles,
        is_active: editActive,
      });

      setIsEditOpen(false);
      setActionSuccess(`User account updated successfully.`);
      fetchUsers();
    } catch (err: unknown) {
      setEditError(err instanceof Error ? err.message : 'Failed to update user account.');
    } finally {
      setEditLoading(false);
    }
  };

  // Handle Status Toggle
  const handleStatusToggleConfirm = async () => {
    if (!statusTarget) return;
    setStatusLoading(true);
    setActionError(null);

    try {
      const nextActive = !statusTarget.is_active;
      await usersApi.setUserStatus(statusTarget.id, nextActive);
      setStatusTarget(null);
      setActionSuccess(
        `User ${statusTarget.username} has been ${nextActive ? 'activated' : 'deactivated'}.`
      );
      fetchUsers();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : 'Failed to change user status.');
      setStatusTarget(null);
    } finally {
      setStatusLoading(false);
    }
  };

  // Handle Delete
  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    setDeleteLoading(true);
    setActionError(null);

    try {
      await usersApi.deleteUser(deleteTarget.id);
      setDeleteTarget(null);
      setActionSuccess(`User account ${deleteTarget.username} has been deleted.`);
      fetchUsers();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : 'Failed to delete user account.');
      setDeleteTarget(null);
    } finally {
      setDeleteLoading(false);
    }
  };

  if (!canReadUsers) {
    return (
      <div className="p-8 max-w-2xl mx-auto">
        <Card className="p-6 border-red-800/80 bg-red-950/20 text-center space-y-4">
          <div className="w-12 h-12 mx-auto rounded-full bg-red-900/40 border border-red-700 flex items-center justify-center text-red-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-slate-100">Access Denied: Administrative Area</h2>
          <p className="text-xs text-slate-400">
            You do not possess the required authorization (<code>users.read</code> or{' '}
            <code>ADMIN</code> role) to view or manage system users.
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 select-none">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <Users className="w-5 h-5 text-blue-400" />
            User Management & Directory
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Provision, manage, and govern operational analyst and administrator accounts.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <Button variant="outline" size="sm" onClick={fetchUsers} className="gap-1.5 text-xs">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
          {canCreateUsers && (
            <Button
              variant="primary"
              size="sm"
              onClick={() => setIsCreateOpen(true)}
              className="gap-1.5 text-xs"
            >
              <UserPlus className="w-3.5 h-3.5" />
              Add User Account
            </Button>
          )}
        </div>
      </div>

      {/* Global Action Feedback Banners */}
      {actionSuccess && (
        <div className="p-3 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
            <span>{actionSuccess}</span>
          </div>
          <button
            onClick={() => setActionSuccess(null)}
            className="text-emerald-400 hover:text-emerald-200 text-xs font-mono"
          >
            ✕
          </button>
        </div>
      )}

      {actionError && (
        <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-400" />
            <span>{actionError}</span>
          </div>
          <button
            onClick={() => setActionError(null)}
            className="text-red-400 hover:text-red-200 text-xs font-mono"
          >
            ✕
          </button>
        </div>
      )}

      {/* Search & Filter Toolbar */}
      <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 bg-surface-300 p-3 rounded-lg border border-slate-800">
        <div className="sm:col-span-6 relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by username, full name, or email..."
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="sm:col-span-3">
          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            aria-label="Filter by system role"
            className="w-full px-3 py-1.5 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 focus:outline-none focus:border-blue-500 font-sans"
          >
            <option value="">All Roles</option>
            {roles.map((r) => (
              <option key={r.id} value={r.name}>
                {r.name}
              </option>
            ))}
          </select>
        </div>

        <div className="sm:col-span-3">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by account status"
            className="w-full px-3 py-1.5 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 focus:outline-none focus:border-blue-500 font-sans"
          >
            <option value="">All Statuses</option>
            <option value="active">Active Accounts</option>
            <option value="deactivated">Deactivated Accounts</option>
          </select>
        </div>
      </div>

      {/* User Directory Table */}
      <Card className="border-slate-800 overflow-hidden bg-surface-300">
        {isLoading ? (
          <div className="p-6 space-y-4">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        ) : users.length === 0 ? (
          <div className="p-12 text-center text-slate-400 space-y-2">
            <Users className="w-8 h-8 mx-auto text-slate-600" />
            <p className="text-sm font-medium">No user accounts found.</p>
            <p className="text-xs text-slate-500">
              Try adjusting your search criteria or role filters.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-surface-400/60 text-slate-400 font-mono text-[11px] uppercase">
                  <th className="py-3 px-4">User Account</th>
                  <th className="py-3 px-4">Email</th>
                  <th className="py-3 px-4">Roles</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Last Active</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {users.map((u) => {
                  const isCurrent = currentUser?.id === u.id;

                  return (
                    <tr key={u.id} className="hover:bg-surface-400/30 transition-colors">
                      {/* Name & Username */}
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-200">
                          {u.full_name || <span className="text-slate-500 italic">No name</span>}
                        </div>
                        <div className="text-[11px] font-mono text-blue-400 flex items-center gap-1.5 mt-0.5">
                          <span>@{u.username}</span>
                          {isCurrent && (
                            <span className="text-[10px] px-1 rounded bg-blue-950 text-blue-300 border border-blue-800 font-mono">
                              YOU
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Email */}
                      <td className="py-3 px-4 font-mono text-slate-300">{u.email}</td>

                      {/* Roles */}
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {u.roles.map((r) => (
                            <Badge
                              key={r}
                              variant={
                                r === 'ADMIN' ? 'danger' : r === 'ANALYST' ? 'primary' : 'outline'
                              }
                              className="font-mono text-[10px] uppercase"
                            >
                              {r}
                            </Badge>
                          ))}
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                            u.is_active
                              ? 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/80'
                              : 'bg-red-950/70 text-red-400 border border-red-800/80'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              u.is_active ? 'bg-emerald-500' : 'bg-red-500'
                            }`}
                          />
                          {u.is_active ? 'ACTIVE' : 'DEACTIVATED'}
                        </span>
                      </td>

                      {/* Last Active */}
                      <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                        {u.last_login_at
                          ? formatDate(u.last_login_at)
                          : u.created_at
                          ? `Created ${formatDate(u.created_at)}`
                          : 'Never'}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {canUpdateUsers && (
                            <>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => openEditModal(u)}
                                className="h-7 w-7 p-0 text-slate-400 hover:text-slate-100"
                                title="Edit User"
                              >
                                <Edit2 className="w-3.5 h-3.5" />
                              </Button>

                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setStatusTarget(u)}
                                className={`h-7 w-7 p-0 ${
                                  u.is_active
                                    ? 'text-amber-400 hover:text-amber-300'
                                    : 'text-emerald-400 hover:text-emerald-300'
                                }`}
                                title={u.is_active ? 'Deactivate Account' : 'Activate Account'}
                              >
                                {u.is_active ? (
                                  <UserX className="w-3.5 h-3.5" />
                                ) : (
                                  <UserCheck className="w-3.5 h-3.5" />
                                )}
                              </Button>
                            </>
                          )}

                          {canDeleteUsers && !isCurrent && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setDeleteTarget(u)}
                              className="h-7 w-7 p-0 text-red-400 hover:text-red-300"
                              title="Delete Account"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* --------------------------------------------------------------- */}
      {/* Create User Modal */}
      {/* --------------------------------------------------------------- */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Create New User Account"
        maxWidth="lg"
      >
        <form onSubmit={handleCreateSubmit} className="space-y-4">
          {createError && (
            <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-400" />
              <span>{createError}</span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Username <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                required
                value={createUsername}
                onChange={(e) => setCreateUsername(e.target.value)}
                placeholder="e.g. jdoe_soc"
                pattern="^[a-zA-Z0-9_\-\.]{3,64}$"
                className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
              />
              <p className="text-[11px] text-slate-500 mt-1">3-64 characters alphanumeric.</p>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Email Address <span className="text-red-400">*</span>
              </label>
              <input
                type="email"
                required
                value={createEmail}
                onChange={(e) => setCreateEmail(e.target.value)}
                placeholder="analyst@sentinelforge.local"
                className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Display Name</label>
            <input
              type="text"
              value={createFullName}
              onChange={(e) => setCreateFullName(e.target.value)}
              placeholder="e.g. John Doe"
              className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-sans"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Initial Password <span className="text-red-400">*</span>
            </label>
            <input
              type="password"
              required
              minLength={12}
              value={createPassword}
              onChange={(e) => setCreatePassword(e.target.value)}
              placeholder="Min 12 characters"
              className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Hashed securely via Argon2id with random salt.
            </p>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-2">
              Assigned System Roles
            </label>
            <div className="space-y-2 p-3 rounded bg-surface-400/50 border border-slate-700">
              {roles.map((r) => {
                const isChecked = createRoles.includes(r.name);
                return (
                  <label
                    key={r.id}
                    className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-300"
                  >
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setCreateRoles([...createRoles, r.name]);
                        } else {
                          setCreateRoles(createRoles.filter((name) => name !== r.name));
                        }
                      }}
                      className="mt-0.5 rounded bg-surface-500 border-slate-600 text-blue-500 focus:ring-0"
                    />
                    <div>
                      <div className="font-semibold text-slate-200">{r.name}</div>
                      <div className="text-[11px] text-slate-400">
                        {r.description || 'System role'}
                      </div>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="flex items-center gap-2 pt-2">
            <input
              type="checkbox"
              id="create_active"
              checked={createActive}
              onChange={(e) => setCreateActive(e.target.checked)}
              className="rounded bg-surface-500 border-slate-600 text-blue-500 focus:ring-0"
            />
            <label htmlFor="create_active" className="text-xs text-slate-300 cursor-pointer">
              Activate account immediately upon creation
            </label>
          </div>

          <div className="pt-4 border-t border-slate-800 flex justify-end gap-3">
            <Button
              variant="ghost"
              type="button"
              onClick={() => setIsCreateOpen(false)}
              disabled={createLoading}
            >
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={createLoading}>
              Create Account
            </Button>
          </div>
        </form>
      </Modal>

      {/* --------------------------------------------------------------- */}
      {/* Edit User Modal */}
      {/* --------------------------------------------------------------- */}
      <Modal
        isOpen={isEditOpen}
        onClose={() => setIsEditOpen(false)}
        title="Edit User Account"
        maxWidth="lg"
      >
        <form onSubmit={handleEditSubmit} className="space-y-4">
          {editError && (
            <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-400" />
              <span>{editError}</span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Username</label>
              <input
                type="text"
                value={editUsername}
                onChange={(e) => setEditUsername(e.target.value)}
                pattern="^[a-zA-Z0-9_\-\.]{3,64}$"
                className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Email Address</label>
              <input
                type="email"
                value={editEmail}
                onChange={(e) => setEditEmail(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Display Name</label>
            <input
              type="text"
              value={editFullName}
              onChange={(e) => setEditFullName(e.target.value)}
              placeholder="e.g. John Doe"
              className="w-full px-3 py-2 text-xs rounded bg-surface-400 border border-slate-700 text-slate-200 focus:outline-none focus:border-blue-500 font-sans"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-2">Assigned Roles</label>
            <div className="space-y-2 p-3 rounded bg-surface-400/50 border border-slate-700">
              {roles.map((r) => {
                const isChecked = editRoles.includes(r.name);
                return (
                  <label
                    key={r.id}
                    className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-300"
                  >
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setEditRoles([...editRoles, r.name]);
                        } else {
                          setEditRoles(editRoles.filter((name) => name !== r.name));
                        }
                      }}
                      className="mt-0.5 rounded bg-surface-500 border-slate-600 text-blue-500 focus:ring-0"
                    />
                    <div>
                      <div className="font-semibold text-slate-200">{r.name}</div>
                      <div className="text-[11px] text-slate-400">
                        {r.description || 'System role'}
                      </div>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="flex items-center gap-2 pt-2">
            <input
              type="checkbox"
              id="edit_active"
              checked={editActive}
              onChange={(e) => setEditActive(e.target.checked)}
              className="rounded bg-surface-500 border-slate-600 text-blue-500 focus:ring-0"
            />
            <label htmlFor="edit_active" className="text-xs text-slate-300 cursor-pointer">
              Account Active
            </label>
          </div>

          <div className="pt-4 border-t border-slate-800 flex justify-end gap-3">
            <Button
              variant="ghost"
              type="button"
              onClick={() => setIsEditOpen(false)}
              disabled={editLoading}
            >
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={editLoading}>
              Save Changes
            </Button>
          </div>
        </form>
      </Modal>

      {/* --------------------------------------------------------------- */}
      {/* Deactivate/Activate ConfirmDialog */}
      {/* --------------------------------------------------------------- */}
      <ConfirmDialog
        isOpen={statusTarget !== null}
        onClose={() => setStatusTarget(null)}
        onConfirm={handleStatusToggleConfirm}
        title={statusTarget?.is_active ? 'Deactivate User Account' : 'Activate User Account'}
        message={
          statusTarget?.is_active
            ? `Are you sure you want to deactivate @${statusTarget?.username}? The user will be prevented from authenticating and all current active sessions will be invalidated immediately.`
            : `Are you sure you want to re-activate @${statusTarget?.username}? The user will be able to log in again.`
        }
        confirmText={statusTarget?.is_active ? 'Deactivate User' : 'Activate User'}
        variant={statusTarget?.is_active ? 'danger' : 'primary'}
        isLoading={statusLoading}
      />

      {/* --------------------------------------------------------------- */}
      {/* Delete User ConfirmDialog */}
      {/* --------------------------------------------------------------- */}
      <ConfirmDialog
        isOpen={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDeleteConfirm}
        title={`Permanently Delete User @${deleteTarget?.username}`}
        message={
          `Warning: Are you sure you want to permanently delete user account @${deleteTarget?.username}? ` +
          `This action is irreversible. If this user has authored security investigation notes or audit trails, ` +
          `deletion will be rejected to preserve forensic integrity, and you will be guided to deactivate the account instead.`
        }
        confirmText="Permanently Delete"
        variant="danger"
        isLoading={deleteLoading}
      />
    </div>
  );
}
