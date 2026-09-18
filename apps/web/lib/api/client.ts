import { APIResponse } from '@/types/api';

export class APIError extends Error {
  public status: number;
  public details?: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.details = details;
  }
}

export class ConcurrencyConflictError extends APIError {
  constructor(message: string = 'Concurrency conflict: Record was updated by another user.') {
    super(message, 409);
    this.name = 'ConcurrencyConflictError';
  }
}

const DEFAULT_HEADERS: HeadersInit = {
  'Content-Type': 'application/json',
  'X-Requested-With': 'XMLHttpRequest', // Anti-CSRF token check required by backend
};

async function handleResponse<T>(response: Response): Promise<T> {
  const isJson = response.headers.get('content-type')?.includes('application/json');
  const payload = isJson ? await response.json() : null;

  if (!response.ok) {
    const errorMsg =
      payload?.detail ||
      payload?.error?.message ||
      `HTTP error ${response.status}: ${response.statusText}`;

    if (response.status === 409) {
      throw new ConcurrencyConflictError(errorMsg);
    }
    throw new APIError(errorMsg, response.status, payload?.error || payload);
  }

  // Handle standard SentinelForge APIResponse envelope: { data: T, meta: {...}, error: null }
  if (payload && typeof payload === 'object' && 'data' in payload) {
    return (payload as APIResponse<T>).data;
  }

  return payload as T;
}

export const apiClient = {
  async get<T>(url: string, init?: RequestInit): Promise<T> {
    const response = await fetch(url, {
      ...init,
      method: 'GET',
      credentials: 'include',
      headers: {
        ...DEFAULT_HEADERS,
        ...init?.headers,
      },
    });
    return handleResponse<T>(response);
  },

  async post<T>(url: string, body?: unknown, init?: RequestInit): Promise<T> {
    const response = await fetch(url, {
      ...init,
      method: 'POST',
      credentials: 'include',
      headers: {
        ...DEFAULT_HEADERS,
        ...init?.headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return handleResponse<T>(response);
  },

  async patch<T>(url: string, body?: unknown, init?: RequestInit): Promise<T> {
    const response = await fetch(url, {
      ...init,
      method: 'PATCH',
      credentials: 'include',
      headers: {
        ...DEFAULT_HEADERS,
        ...init?.headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return handleResponse<T>(response);
  },

  async put<T>(url: string, body?: unknown, init?: RequestInit): Promise<T> {
    const response = await fetch(url, {
      ...init,
      method: 'PUT',
      credentials: 'include',
      headers: {
        ...DEFAULT_HEADERS,
        ...init?.headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return handleResponse<T>(response);
  },

  async delete<T>(url: string, init?: RequestInit): Promise<T> {
    const response = await fetch(url, {
      ...init,
      method: 'DELETE',
      credentials: 'include',
      headers: {
        ...DEFAULT_HEADERS,
        ...init?.headers,
      },
    });
    return handleResponse<T>(response);
  },
};
