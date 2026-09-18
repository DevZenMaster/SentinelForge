export interface ResponseMetadata {
  timestamp: string;
  request_id?: string;
}

export interface APIErrorDetail {
  code?: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface APIResponse<T> {
  data: T;
  meta: ResponseMetadata;
  error?: APIErrorDetail | null;
}

export interface PaginatedList<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}
