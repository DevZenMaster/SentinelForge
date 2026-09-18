/**
 * API client library for Notifications, Integrations, and Policies (Phase 13).
 */

import { apiClient } from './client';
import {
  Integration,
  IntegrationCreate,
  IntegrationUpdate,
  NotificationPolicy,
  NotificationPolicyCreate,
  NotificationPolicyUpdate,
  NotificationDelivery,
  NotificationTestResponse,
} from '@/types/notifications';
import { APIResponse } from '@/types/api';

function buildQuery(params?: Record<string, unknown>): string {
  if (!params) return '';
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.append(key, String(value));
    }
  }
  const query = searchParams.toString();
  return query ? `?${query}` : '';
}

export const notificationsApi = {
  // Integrations
  listIntegrations: (params?: { type?: string; enabled?: boolean }) =>
    apiClient.get<APIResponse<Integration[]>>(`/api/v1/integrations${buildQuery(params)}`),

  getIntegration: (id: string) =>
    apiClient.get<APIResponse<Integration>>(`/api/v1/integrations/${id}`),

  createIntegration: (data: IntegrationCreate) =>
    apiClient.post<APIResponse<Integration>>('/api/v1/integrations', data),

  updateIntegration: (id: string, data: IntegrationUpdate) =>
    apiClient.patch<APIResponse<Integration>>(`/api/v1/integrations/${id}`, data),

  enableIntegration: (id: string) =>
    apiClient.post<APIResponse<Integration>>(`/api/v1/integrations/${id}/enable`),

  disableIntegration: (id: string) =>
    apiClient.post<APIResponse<Integration>>(`/api/v1/integrations/${id}/disable`),

  deleteIntegration: (id: string) =>
    apiClient.delete<APIResponse<{ message: string }>>(`/api/v1/integrations/${id}`),

  testIntegration: (id: string, customMessage?: string) =>
    apiClient.post<APIResponse<NotificationTestResponse>>(`/api/v1/integrations/${id}/test`, {
      custom_message: customMessage,
    }),

  // Policies
  listPolicies: (params?: { enabled?: boolean }) =>
    apiClient.get<APIResponse<NotificationPolicy[]>>(`/api/v1/notification-policies${buildQuery(params)}`),

  getPolicy: (id: string) =>
    apiClient.get<APIResponse<NotificationPolicy>>(`/api/v1/notification-policies/${id}`),

  createPolicy: (data: NotificationPolicyCreate) =>
    apiClient.post<APIResponse<NotificationPolicy>>('/api/v1/notification-policies', data),

  updatePolicy: (id: string, data: NotificationPolicyUpdate) =>
    apiClient.patch<APIResponse<NotificationPolicy>>(`/api/v1/notification-policies/${id}`, data),

  enablePolicy: (id: string) =>
    apiClient.post<APIResponse<NotificationPolicy>>(`/api/v1/notification-policies/${id}/enable`),

  disablePolicy: (id: string) =>
    apiClient.post<APIResponse<NotificationPolicy>>(`/api/v1/notification-policies/${id}/disable`),

  // Deliveries
  listDeliveries: (params?: {
    status?: string;
    event_type?: string;
    destination_id?: string;
    policy_id?: string;
    skip?: number;
    limit?: number;
  }) =>
    apiClient.get<APIResponse<NotificationDelivery[]>>(`/api/v1/notifications${buildQuery(params)}`),

  getDelivery: (id: string) =>
    apiClient.get<APIResponse<NotificationDelivery>>(`/api/v1/notifications/${id}`),

  retryDelivery: (id: string) =>
    apiClient.post<APIResponse<NotificationDelivery>>(`/api/v1/notifications/${id}/retry`),

  cancelDelivery: (id: string) =>
    apiClient.post<APIResponse<NotificationDelivery>>(`/api/v1/notifications/${id}/cancel`),
};
