import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import UserSettingsPage from '@/app/settings/page';
import AdminUsersPage from '@/app/admin/users/page';
import { useAuth } from '@/lib/auth/context';
import { usersApi } from '@/lib/api/users';
import { UserDetail, UserAdminListItem, RoleItem } from '@/types/users';

vi.mock('@/lib/auth/context', () => ({
  useAuth: vi.fn(),
}));

vi.mock('@/lib/api/users', () => ({
  usersApi: {
    getMyProfile: vi.fn(),
    updateMyProfile: vi.fn(),
    changeMyPassword: vi.fn(),
    listRoles: vi.fn(),
    listUsers: vi.fn(),
    createUser: vi.fn(),
    getUser: vi.fn(),
    updateUser: vi.fn(),
    setUserStatus: vi.fn(),
    deleteUser: vi.fn(),
  },
}));

const mockProfile: UserDetail = {
  id: 'user-uuid-1',
  username: 'analyst_bob',
  email: 'bob@sentinelforge.local',
  full_name: 'Bob Analyst',
  is_active: true,
  is_superuser: false,
  roles: ['ANALYST'],
  permissions: ['alerts.read', 'alerts.triage', 'events.read'],
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
  last_login_at: '2026-09-18T12:00:00Z',
};

const mockAdminUsers: UserAdminListItem[] = [
  {
    id: 'user-admin-1',
    username: 'admin',
    email: 'admin@sentinelforge.local',
    full_name: 'System Administrator',
    is_active: true,
    roles: ['ADMIN'],
    created_at: '2026-09-01T00:00:00Z',
    last_login_at: '2026-09-18T10:00:00Z',
  },
  {
    id: 'user-analyst-2',
    username: 'alice_soc',
    email: 'alice@sentinelforge.local',
    full_name: 'Alice Smith',
    is_active: true,
    roles: ['ANALYST'],
    created_at: '2026-09-05T00:00:00Z',
    last_login_at: '2026-09-18T11:00:00Z',
  },
  {
    id: 'user-viewer-3',
    username: 'viewer_guest',
    email: 'guest@sentinelforge.local',
    full_name: 'Guest Viewer',
    is_active: false,
    roles: ['VIEWER'],
    created_at: '2026-09-10T00:00:00Z',
    last_login_at: null,
  },
];

const mockRoles: RoleItem[] = [
  { id: 'r-1', name: 'ADMIN', description: 'System Administrator' },
  { id: 'r-2', name: 'ANALYST', description: 'SOC Analyst' },
  { id: 'r-3', name: 'VIEWER', description: 'Read-only Viewer' },
];

describe('Phase 15: User Settings Page (/settings)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useAuth as any).mockReturnValue({
      user: { id: 'user-uuid-1', username: 'analyst_bob' },
      refresh: vi.fn(),
      hasPermission: vi.fn().mockReturnValue(true),
      hasRole: vi.fn().mockReturnValue(false),
    });
    (usersApi.getMyProfile as any).mockResolvedValue(mockProfile);
  });

  it('renders user profile details and capabilities', async () => {
    render(<UserSettingsPage />);

    await waitFor(() => {
      expect(screen.getByText('User Settings & Profile')).toBeInTheDocument();
      expect(screen.getByDisplayValue('analyst_bob')).toBeInTheDocument();
      expect(screen.getByDisplayValue('bob@sentinelforge.local')).toBeInTheDocument();
      expect(screen.getByDisplayValue('Bob Analyst')).toBeInTheDocument();
      expect(screen.getByText('alerts.read')).toBeInTheDocument();
      expect(screen.getByText('alerts.triage')).toBeInTheDocument();
    });
  });

  it('updates display name successfully', async () => {
    (usersApi.updateMyProfile as any).mockResolvedValue({
      ...mockProfile,
      full_name: 'Robert Analyst',
    });

    render(<UserSettingsPage />);

    await waitFor(() => {
      expect(screen.getByDisplayValue('Bob Analyst')).toBeInTheDocument();
    });

    const nameInput = screen.getByDisplayValue('Bob Analyst');
    fireEvent.change(nameInput, { target: { value: 'Robert Analyst' } });

    const saveBtn = screen.getByRole('button', { name: /save profile changes/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(usersApi.updateMyProfile).toHaveBeenCalledWith({
        full_name: 'Robert Analyst',
        username: 'analyst_bob',
      });
      expect(screen.getByText('Profile successfully updated.')).toBeInTheDocument();
    });
  });

  it('submits password change with validation', async () => {
    (usersApi.changeMyPassword as any).mockResolvedValue({
      message: 'Password successfully changed.',
    });

    render(<UserSettingsPage />);

    await waitFor(() => {
      expect(screen.getByText('Change Password')).toBeInTheDocument();
    });

    // Fill password form
    const currentInput = screen.getByPlaceholderText('••••••••••••');
    const newInput = screen.getByPlaceholderText('Min 12 characters');
    const confirmInput = screen.getByPlaceholderText('Repeat new password');

    fireEvent.change(currentInput, { target: { value: 'OldPassword123!' } });
    fireEvent.change(newInput, { target: { value: 'NewSuperPassword2026!' } });
    fireEvent.change(confirmInput, { target: { value: 'NewSuperPassword2026!' } });

    const changeBtn = screen.getByRole('button', { name: /update password/i });
    fireEvent.click(changeBtn);

    await waitFor(() => {
      expect(usersApi.changeMyPassword).toHaveBeenCalledWith({
        current_password: 'OldPassword123!',
        new_password: 'NewSuperPassword2026!',
        confirm_password: 'NewSuperPassword2026!',
      });
      expect(screen.getByText('Password successfully changed.')).toBeInTheDocument();
    });
  });
});

describe('Phase 15: Admin User Management Page (/admin/users)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('blocks unauthorized users when lacking permissions and role', async () => {
    (useAuth as any).mockReturnValue({
      user: { id: 'viewer-id', username: 'viewer' },
      hasPermission: vi.fn().mockReturnValue(false),
      hasRole: vi.fn().mockReturnValue(false),
    });

    render(<AdminUsersPage />);

    expect(screen.getByText(/Access Denied: Administrative Area/i)).toBeInTheDocument();
    expect(usersApi.listUsers).not.toHaveBeenCalled();
  });

  it('renders user directory and roles for authorized administrator', async () => {
    (useAuth as any).mockReturnValue({
      user: { id: 'user-admin-1', username: 'admin' },
      hasPermission: vi.fn().mockReturnValue(true),
      hasRole: vi.fn().mockReturnValue(true),
    });
    (usersApi.listUsers as any).mockResolvedValue({
      items: mockAdminUsers,
      total: 3,
    });
    (usersApi.listRoles as any).mockResolvedValue({
      items: mockRoles,
      total: 3,
    });

    render(<AdminUsersPage />);

    await waitFor(() => {
      expect(screen.getByText('User Management & Directory')).toBeInTheDocument();
      expect(screen.getByText('@admin')).toBeInTheDocument();
      expect(screen.getByText('@alice_soc')).toBeInTheDocument();
      expect(screen.getByText('@viewer_guest')).toBeInTheDocument();
      expect(screen.getByText('alice@sentinelforge.local')).toBeInTheDocument();
    });
  });

  it('opens and submits create user modal', async () => {
    (useAuth as any).mockReturnValue({
      user: { id: 'user-admin-1', username: 'admin' },
      hasPermission: vi.fn().mockReturnValue(true),
      hasRole: vi.fn().mockReturnValue(true),
    });
    (usersApi.listUsers as any).mockResolvedValue({
      items: mockAdminUsers,
      total: 3,
    });
    (usersApi.listRoles as any).mockResolvedValue({
      items: mockRoles,
      total: 3,
    });
    (usersApi.createUser as any).mockResolvedValue({
      id: 'new-user-id',
      username: 'charlie_soc',
      email: 'charlie@sentinelforge.local',
      full_name: 'Charlie Brown',
      is_active: true,
      roles: ['ANALYST'],
      permissions: [],
      created_at: '2026-09-18T12:00:00Z',
      updated_at: '2026-09-18T12:00:00Z',
    });

    render(<AdminUsersPage />);

    await waitFor(() => {
      expect(screen.getByText('Add User Account')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Add User Account'));

    await waitFor(() => {
      expect(screen.getByText('Create New User Account')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText('e.g. jdoe_soc'), {
      target: { value: 'charlie_soc' },
    });
    fireEvent.change(screen.getByPlaceholderText('analyst@sentinelforge.local'), {
      target: { value: 'charlie@sentinelforge.local' },
    });
    fireEvent.change(screen.getByPlaceholderText('Min 12 characters'), {
      target: { value: 'CharliePassword123!' },
    });

    const submitBtn = screen.getByRole('button', { name: /create account/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(usersApi.createUser).toHaveBeenCalledWith(
        expect.objectContaining({
          username: 'charlie_soc',
          email: 'charlie@sentinelforge.local',
          password: 'CharliePassword123!',
          is_active: true,
        })
      );
    });
  });

  it('triggers activation toggle confirmation', async () => {
    (useAuth as any).mockReturnValue({
      user: { id: 'user-admin-1', username: 'admin' },
      hasPermission: vi.fn().mockReturnValue(true),
      hasRole: vi.fn().mockReturnValue(true),
    });
    (usersApi.listUsers as any).mockResolvedValue({
      items: mockAdminUsers,
      total: 3,
    });
    (usersApi.listRoles as any).mockResolvedValue({
      items: mockRoles,
      total: 3,
    });
    (usersApi.setUserStatus as any).mockResolvedValue({
      ...mockAdminUsers[1],
      is_active: false,
    });

    render(<AdminUsersPage />);

    await waitFor(() => {
      expect(screen.getByText('@alice_soc')).toBeInTheDocument();
    });

    const deactButtons = screen.getAllByTitle('Deactivate Account');
    fireEvent.click(deactButtons[1]); // Click deactivate on alice_soc

    await waitFor(() => {
      expect(screen.getByText(/Deactivate User Account/i)).toBeInTheDocument();
      expect(screen.getByText(/Are you sure you want to deactivate @alice_soc/i)).toBeInTheDocument();
    });

    const confirmBtn = screen.getByRole('button', { name: 'Deactivate User' });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(usersApi.setUserStatus).toHaveBeenCalledWith('user-analyst-2', false);
    });
  });
});
