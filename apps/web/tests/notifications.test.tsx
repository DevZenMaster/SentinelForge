import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import IntegrationsPage from '@/app/integrations/page';
import NotificationPoliciesPage from '@/app/notification-policies/page';
import NotificationDeliveriesPage from '@/app/notifications/page';
import { useAuth } from '@/lib/auth/context';
import { notificationsApi } from '@/lib/api/notifications';
import { Integration, NotificationPolicy, NotificationDelivery } from '@/types/notifications';

vi.mock('@/lib/auth/context', () => ({
  useAuth: vi.fn(),
}));

vi.mock('@/lib/api/notifications', () => ({
  notificationsApi: {
    listIntegrations: vi.fn(),
    getIntegration: vi.fn(),
    createIntegration: vi.fn(),
    updateIntegration: vi.fn(),
    enableIntegration: vi.fn(),
    disableIntegration: vi.fn(),
    deleteIntegration: vi.fn(),
    testIntegration: vi.fn(),

    listPolicies: vi.fn(),
    getPolicy: vi.fn(),
    createPolicy: vi.fn(),
    updatePolicy: vi.fn(),
    enablePolicy: vi.fn(),
    disablePolicy: vi.fn(),

    listDeliveries: vi.fn(),
    getDelivery: vi.fn(),
    retryDelivery: vi.fn(),
    cancelDelivery: vi.fn(),
  },
}));

const mockIntegrations: Integration[] = [
  {
    id: '11111111-1111-1111-1111-111111111111',
    name: 'Primary Security Webhook',
    type: 'WEBHOOK',
    enabled: true,
    endpoint_url: 'https://soc.example.com/alerts',
    email_recipients: null,
    is_secret_configured: true,
    secret_preview: '••••••••abcd',
    created_by_user_id: 'admin-id',
    updated_by_user_id: 'admin-id',
    last_delivery_at: '2026-09-18T10:00:00Z',
    last_successful_delivery_at: '2026-09-18T10:00:00Z',
    last_failed_delivery_at: null,
    version: 1,
    created_at: '2026-09-18T08:00:00Z',
    updated_at: '2026-09-18T08:00:00Z',
  },
  {
    id: '22222222-2222-2222-2222-222222222222',
    name: 'SOC Oncall Email',
    type: 'EMAIL',
    enabled: false,
    endpoint_url: null,
    email_recipients: ['tier1@example.com', 'tier2@example.com'],
    is_secret_configured: false,
    secret_preview: null,
    created_by_user_id: 'admin-id',
    updated_by_user_id: 'admin-id',
    last_delivery_at: null,
    last_successful_delivery_at: null,
    last_failed_delivery_at: null,
    version: 1,
    created_at: '2026-09-18T08:00:00Z',
    updated_at: '2026-09-18T08:00:00Z',
  },
];

const mockPolicies: NotificationPolicy[] = [
  {
    id: '33333333-3333-3333-3333-333333333333',
    name: 'Critical Alert Dispatcher',
    description: 'Routes all high and critical alerts to primary webhook',
    enabled: true,
    event_types: ['ALERT_CREATED', 'ALERT_ESCALATED'],
    min_severity: 'HIGH',
    destination_ids: ['11111111-1111-1111-1111-111111111111'],
    filters: { status: 'OPEN' },
    cooldown_seconds: 300,
    created_by_user_id: 'admin-id',
    updated_by_user_id: 'admin-id',
    version: 1,
    created_at: '2026-09-18T08:00:00Z',
    updated_at: '2026-09-18T08:00:00Z',
  },
];

const mockDeliveries: NotificationDelivery[] = [
  {
    id: '44444444-4444-4444-4444-444444444444',
    event_id: 'event-uuid-1',
    event_type: 'ALERT_CREATED',
    source_resource_type: 'alert',
    source_resource_id: 'alert-101',
    policy_id: '33333333-3333-3333-3333-333333333333',
    policy_name: 'Critical Incident & Alert Dispatch',
    destination_id: '11111111-1111-1111-1111-111111111111',
    destination_name: 'Primary Security Webhook',
    destination_type: 'WEBHOOK',
    idempotency_key: 'event-uuid-1:policy-1:dest-1',
    status: 'DELIVERED',
    attempt_count: 1,
    max_attempts: 3,
    first_attempted_at: '2026-09-18T10:00:00Z',
    last_attempted_at: '2026-09-18T10:00:01Z',
    delivered_at: '2026-09-18T10:00:01Z',
    next_retry_at: null,
    http_status: 200,
    response_metadata: { duration_ms: 120 },
    failure_reason: null,
    latency_ms: 120,
    created_at: '2026-09-18T10:00:00Z',
    updated_at: '2026-09-18T10:00:01Z',
    event: {
      id: 'event-uuid-1',
      event_type: 'ALERT_CREATED',
      source_resource_type: 'alert',
      source_resource_id: 'alert-101',
      payload: { title: 'Brute Force Attack Detected', severity: 'HIGH' },
      created_at: '2026-09-18T10:00:00Z',
    },
    destination: {
      id: '11111111-1111-1111-1111-111111111111',
      name: 'Primary Security Webhook',
      type: 'WEBHOOK',
      endpoint_url: 'https://soc.example.com/alerts',
    },
  },
  {
    id: '55555555-5555-5555-5555-555555555555',
    event_id: 'event-uuid-2',
    event_type: 'INCIDENT_CREATED',
    source_resource_type: 'incident',
    source_resource_id: 'inc-202',
    policy_id: '33333333-3333-3333-3333-333333333333',
    policy_name: 'Critical Incident & Alert Dispatch',
    destination_id: '11111111-1111-1111-1111-111111111111',
    destination_name: 'Primary Security Webhook',
    destination_type: 'WEBHOOK',
    idempotency_key: 'event-uuid-2:policy-1:dest-1',
    status: 'EXHAUSTED',
    attempt_count: 3,
    max_attempts: 3,
    first_attempted_at: '2026-09-18T09:00:00Z',
    last_attempted_at: '2026-09-18T09:05:00Z',
    delivered_at: null,
    next_retry_at: null,
    http_status: 503,
    response_metadata: { error: 'Service Unavailable' },
    failure_reason: 'Exceeded max attempts (3). Last error: HTTP 503',
    latency_ms: 1500,
    created_at: '2026-09-18T09:00:00Z',
    updated_at: '2026-09-18T09:05:00Z',
    event: {
      id: 'event-uuid-2',
      event_type: 'INCIDENT_CREATED',
      source_resource_type: 'incident',
      source_resource_id: 'inc-202',
      payload: { title: 'Ransomware Outbreak', severity: 'CRITICAL' },
      created_at: '2026-09-18T09:00:00Z',
    },
    destination: {
      id: '11111111-1111-1111-1111-111111111111',
      name: 'Primary Security Webhook',
      type: 'WEBHOOK',
      endpoint_url: 'https://soc.example.com/alerts',
    },
  },
];

describe('Phase 13: Notification Workspaces Frontend Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Integrations Workspace (/integrations)', () => {
    it('blocks access when integrations.read permission is missing', async () => {
      vi.mocked(useAuth).mockReturnValue({
        hasPermission: vi.fn().mockReturnValue(false),
        roles: ['ROLE_VIEWER'],
      } as any);

      render(<IntegrationsPage />);
      expect(screen.getByText(/Access Denied/i)).toBeInTheDocument();
      expect(
        screen.getByText(/You do not possess the 'integrations.read' permission/i)
      ).toBeInTheDocument();
    });

    it('renders configured destinations and masked secret previews', async () => {
      vi.mocked(useAuth).mockReturnValue({
        hasPermission: vi.fn().mockReturnValue(true),
        roles: ['ROLE_ADMIN'],
      } as any);

      vi.mocked(notificationsApi.listIntegrations).mockResolvedValue({
        data: mockIntegrations,
      } as any);

      render(<IntegrationsPage />);

      await waitFor(() => {
        expect(screen.getByText('Primary Security Webhook')).toBeInTheDocument();
        expect(screen.getByText('SOC Oncall Email')).toBeInTheDocument();
      });

      // Secret preview is masked
      expect(screen.getByText('••••••••abcd')).toBeInTheDocument();
      expect(screen.getByText('https://soc.example.com/alerts')).toBeInTheDocument();
      expect(screen.getByText(/tier1@example.com/)).toBeInTheDocument();
    });

    it('handles test connection dispatch and displays result modal', async () => {
      vi.mocked(useAuth).mockReturnValue({
        hasPermission: vi.fn().mockReturnValue(true),
        roles: ['ROLE_ADMIN'],
      } as any);

      vi.mocked(notificationsApi.listIntegrations).mockResolvedValue({
        data: mockIntegrations,
      } as any);

      vi.mocked(notificationsApi.testIntegration).mockResolvedValue({
        data: {
          destination_id: '11111111-1111-1111-1111-111111111111',
          destination_type: 'WEBHOOK',
          status: 'SUCCESS',
          latency_ms: 145,
          http_status: 200,
        },
      } as any);

      render(<IntegrationsPage />);

      await waitFor(() => {
        expect(screen.getByText('Primary Security Webhook')).toBeInTheDocument();
      });

      const testButtons = screen.getAllByRole('button', { name: /Test/i });
      fireEvent.click(testButtons[0]);

      await waitFor(() => {
        expect(notificationsApi.testIntegration).toHaveBeenCalledWith('11111111-1111-1111-1111-111111111111');
        expect(screen.getByText('Delivery Successful')).toBeInTheDocument();
        expect(screen.getByText('145 ms')).toBeInTheDocument();
      });
    });
  });

  describe('Notification Policies Workspace (/notification-policies)', () => {
    it('blocks access when notification_policies.read permission is missing', async () => {
      vi.mocked(useAuth).mockReturnValue({
        hasPermission: vi.fn().mockReturnValue(false),
        roles: ['ROLE_VIEWER'],
      } as any);

      render(<NotificationPoliciesPage />);
      expect(screen.getByText(/Access Denied/i)).toBeInTheDocument();
      expect(
        screen.getByText(/You do not possess the 'notification_policies.read' permission/i)
      ).toBeInTheDocument();
    });

    it('renders policies with triggers, severity badge, and destination bindings', async () => {
      vi.mocked(useAuth).mockReturnValue({
        hasPermission: vi.fn().mockReturnValue(true),
        roles: ['ROLE_ADMIN'],
      } as any);

      vi.mocked(notificationsApi.listPolicies).mockResolvedValue({
        data: mockPolicies,
      } as any);
      vi.mocked(notificationsApi.listIntegrations).mockResolvedValue({
        data: mockIntegrations,
      } as any);

      render(<NotificationPoliciesPage />);

      await waitFor(() => {
        expect(screen.getByText('Critical Alert Dispatcher')).toBeInTheDocument();
        expect(screen.getByText('ALERT_CREATED')).toBeInTheDocument();
        expect(screen.getByText('ALERT_ESCALATED')).toBeInTheDocument();
        expect(screen.getByText('≥ HIGH')).toBeInTheDocument();
        expect(screen.getByText('Cooldown: 300s')).toBeInTheDocument();
      });
    });
  });

  describe('Delivery Logs Workspace (/notifications)', () => {
    it('blocks access when notifications.read permission is missing', async () => {
      vi.mocked(useAuth).mockReturnValue({
        hasPermission: vi.fn().mockReturnValue(false),
        roles: ['ROLE_VIEWER'],
      } as any);

      render(<NotificationDeliveriesPage />);
      expect(screen.getByText(/Access Denied/i)).toBeInTheDocument();
      expect(
        screen.getByText(/You do not possess the 'notifications.read' permission/i)
      ).toBeInTheDocument();
    });

    it('renders delivery attempts, status badges, and KPI counters', async () => {
      vi.mocked(useAuth).mockReturnValue({
        hasPermission: vi.fn().mockReturnValue(true),
        roles: ['ROLE_ADMIN'],
      } as any);

      vi.mocked(notificationsApi.listDeliveries).mockResolvedValue({
        data: mockDeliveries,
      } as any);

      render(<NotificationDeliveriesPage />);

      await waitFor(() => {
        expect(screen.getByText('ALERT_CREATED')).toBeInTheDocument();
        expect(screen.getByText('INCIDENT_CREATED')).toBeInTheDocument();
        expect(screen.getAllByText('DELIVERED').length).toBeGreaterThanOrEqual(1);
        expect(screen.getAllByText('EXHAUSTED').length).toBeGreaterThanOrEqual(1);
      });

      // KPI Counters (1 delivered, 1 failed/exhausted)
      expect(screen.getByText('Delivered Successfully')).toBeInTheDocument();
      expect(screen.getByText('Failed / Exhausted')).toBeInTheDocument();
    });

    it('allows manual retry of exhausted delivery when authorized', async () => {
      vi.mocked(useAuth).mockReturnValue({
        hasPermission: vi.fn().mockImplementation((perm: string) => true),
        roles: ['ROLE_ADMIN'],
      } as any);

      vi.mocked(notificationsApi.listDeliveries).mockResolvedValue({
        data: mockDeliveries,
      } as any);
      vi.mocked(notificationsApi.retryDelivery).mockResolvedValue({
        data: { ...mockDeliveries[1], status: 'PENDING' },
      } as any);

      render(<NotificationDeliveriesPage />);

      await waitFor(() => {
        expect(screen.getByText('EXHAUSTED')).toBeInTheDocument();
      });

      const retryBtn = screen.getByTitle('Manual Retry Dispatch');
      expect(retryBtn).toBeInTheDocument();
      fireEvent.click(retryBtn);

      await waitFor(() => {
        expect(notificationsApi.retryDelivery).toHaveBeenCalledWith('55555555-5555-5555-5555-555555555555');
      });
    });
  });
});
