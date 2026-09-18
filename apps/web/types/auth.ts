export interface User {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
  is_active: boolean;
  is_superuser?: boolean;
}

export interface UserContext {
  user: User;
  roles: string[];
  permissions: string[];
}

export interface UserListItem {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
  is_active: boolean;
  roles: string[];
}
