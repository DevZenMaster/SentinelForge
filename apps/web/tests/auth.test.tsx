import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthProvider, useAuth } from '@/lib/auth/context';
import { apiClient } from '@/lib/api/client';

vi.mock('@/lib/api/client', () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
  },
}));

const TestConsumer = () => {
  const { user, roles, permissions, hasRole, hasPermission, isLoading } = useAuth();
  if (isLoading) return <div>Loading...</div>;
  return (
    <div>
      <div data-testid="username">{user?.username || 'anonymous'}</div>
      <div data-testid="is-analyst">{hasRole('ANALYST') ? 'yes' : 'no'}</div>
      <div data-testid="can-assign">{hasPermission('alerts.assign') ? 'yes' : 'no'}</div>
      <div data-testid="can-delete-user">{hasPermission('users.delete') ? 'yes' : 'no'}</div>
    </div>
  );
};

describe('Authentication & Authoritative RBAC Context', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('resolves authenticated analyst profile and evaluates RBAC capabilities', async () => {
    (apiClient.get as any).mockResolvedValueOnce({
      id: 'analyst-1',
      username: 'lead_analyst',
      email: 'analyst@sentinelforge.local',
      full_name: 'Lead Analyst',
      is_active: true,
      roles: ['ANALYST'],
      permissions: ['alerts.read', 'alerts.assign', 'alerts.triage'],
    });

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    );

    expect(screen.getByText('Loading...')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId('username')).toHaveTextContent('lead_analyst');
      expect(screen.getByTestId('is-analyst')).toHaveTextContent('yes');
      expect(screen.getByTestId('can-assign')).toHaveTextContent('yes');
      expect(screen.getByTestId('can-delete-user')).toHaveTextContent('no');
    });
  });

  it('handles unauthenticated state gracefully without granting permissions', async () => {
    (apiClient.get as any).mockRejectedValueOnce(new Error('401 Unauthorized'));

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('username')).toHaveTextContent('anonymous');
      expect(screen.getByTestId('is-analyst')).toHaveTextContent('no');
      expect(screen.getByTestId('can-assign')).toHaveTextContent('no');
    });
  });
});
