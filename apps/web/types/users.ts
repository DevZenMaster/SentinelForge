export interface UserDetail {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
  is_active: boolean;
  is_superuser: boolean;
  roles: string[];
  permissions: string[];
  created_at: string;
  updated_at: string;
  last_login_at?: string | null;
}

export interface UserAdminListItem {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
  is_active: boolean;
  roles: string[];
  created_at?: string | null;
  last_login_at?: string | null;
}

export interface UserListResponse {
  items: UserAdminListItem[];
  total: number;
}

export interface RoleItem {
  id: string;
  name: string;
  description?: string | null;
}

export interface RoleListResponse {
  items: RoleItem[];
  total: number;
}

export interface UserProfileUpdateRequest {
  full_name?: string | null;
  username?: string | null;
}

export interface PasswordChangeRequest {
  current_password: string;
  new_password: string;
  confirm_password: string;
}

export interface UserCreateRequest {
  username: string;
  email: string;
  full_name?: string | null;
  password: string;
  roles: string[];
  is_active: boolean;
}

export interface UserAdminUpdateRequest {
  username?: string | null;
  email?: string | null;
  full_name?: string | null;
  roles?: string[] | null;
  is_active?: boolean | null;
}

export interface UserStatusUpdateRequest {
  is_active: boolean;
}
