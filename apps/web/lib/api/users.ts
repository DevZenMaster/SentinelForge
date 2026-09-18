import { apiClient } from '@/lib/api/client';
import {
  PasswordChangeRequest,
  RoleListResponse,
  UserAdminUpdateRequest,
  UserCreateRequest,
  UserDetail,
  UserListResponse,
  UserProfileUpdateRequest,
} from '@/types/users';

export const usersApi = {
  /**
   * Retrieve profile for current authenticated user.
   */
  async getMyProfile(): Promise<UserDetail> {
    return apiClient.get<UserDetail>('/api/v1/users/me');
  },

  /**
   * Update profile for current authenticated user (display name, username).
   */
  async updateMyProfile(payload: UserProfileUpdateRequest): Promise<UserDetail> {
    return apiClient.patch<UserDetail>('/api/v1/users/me', payload);
  },

  /**
   * Change password for current authenticated user with session revocation.
   */
  async changeMyPassword(payload: PasswordChangeRequest): Promise<{ message: string }> {
    return apiClient.post<{ message: string }>('/api/v1/users/me/change-password', payload);
  },

  /**
   * List available system roles for user assignment.
   */
  async listRoles(): Promise<RoleListResponse> {
    return apiClient.get<RoleListResponse>('/api/v1/users/roles');
  },

  /**
   * List user accounts with optional search and filters.
   */
  async listUsers(params?: {
    search?: string;
    role?: string;
    is_active?: boolean;
  }): Promise<UserListResponse> {
    const query = new URLSearchParams();
    if (params?.search) query.set('search', params.search);
    if (params?.role) query.set('role', params.role);
    if (params?.is_active !== undefined) query.set('is_active', String(params.is_active));

    const qs = query.toString();
    const url = `/api/v1/users${qs ? `?${qs}` : ''}`;
    return apiClient.get<UserListResponse>(url);
  },

  /**
   * Create a new user account (Admin).
   */
  async createUser(payload: UserCreateRequest): Promise<UserDetail> {
    return apiClient.post<UserDetail>('/api/v1/users', payload);
  },

  /**
   * Retrieve single user details by ID (Admin).
   */
  async getUser(userId: string): Promise<UserDetail> {
    return apiClient.get<UserDetail>(`/api/v1/users/${userId}`);
  },

  /**
   * Update user details and role bindings by ID (Admin).
   */
  async updateUser(userId: string, payload: UserAdminUpdateRequest): Promise<UserDetail> {
    return apiClient.patch<UserDetail>(`/api/v1/users/${userId}`, payload);
  },

  /**
   * Activate or deactivate a user account (Admin).
   */
  async setUserStatus(userId: string, isActive: boolean): Promise<UserDetail> {
    return apiClient.post<UserDetail>(`/api/v1/users/${userId}/status`, { is_active: isActive });
  },

  /**
   * Delete a user account (Admin).
   */
  async deleteUser(userId: string): Promise<{ message: string }> {
    return apiClient.delete<{ message: string }>(`/api/v1/users/${userId}`);
  },
};
