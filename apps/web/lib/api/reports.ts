import { apiClient } from './client';
import {
  AlertPerformanceReport,
  AnalystActivityReport,
  ComplianceEvidenceReport,
  DetectionReport,
  IncidentReport,
  OperationsSummaryReport,
  ReportExportFormat,
  ReportType,
  SecurityAuditReport,
  SLAReport,
  ThreatIntelReport,
} from '@/types/reports';

function buildQueryParams(startTime?: string, endTime?: string): string {
  const params = new URLSearchParams();
  if (startTime) params.append('start_time', startTime);
  if (endTime) params.append('end_time', endTime);
  const query = params.toString();
  return query ? `?${query}` : '';
}

export async function fetchSummaryReport(
  startTime?: string,
  endTime?: string
): Promise<OperationsSummaryReport> {
  return apiClient.get<OperationsSummaryReport>(
    `/api/v1/reports/summary${buildQueryParams(startTime, endTime)}`
  );
}

export async function fetchAlertsReport(
  startTime?: string,
  endTime?: string
): Promise<AlertPerformanceReport> {
  return apiClient.get<AlertPerformanceReport>(
    `/api/v1/reports/alerts${buildQueryParams(startTime, endTime)}`
  );
}

export async function fetchIncidentsReport(
  startTime?: string,
  endTime?: string
): Promise<IncidentReport> {
  return apiClient.get<IncidentReport>(
    `/api/v1/reports/incidents${buildQueryParams(startTime, endTime)}`
  );
}

export async function fetchDetectionsReport(
  startTime?: string,
  endTime?: string
): Promise<DetectionReport> {
  return apiClient.get<DetectionReport>(
    `/api/v1/reports/detections${buildQueryParams(startTime, endTime)}`
  );
}

export async function fetchSLAReport(
  startTime?: string,
  endTime?: string
): Promise<SLAReport> {
  return apiClient.get<SLAReport>(
    `/api/v1/reports/sla${buildQueryParams(startTime, endTime)}`
  );
}

export async function fetchThreatIntelReport(
  startTime?: string,
  endTime?: string
): Promise<ThreatIntelReport> {
  return apiClient.get<ThreatIntelReport>(
    `/api/v1/reports/threat-intelligence${buildQueryParams(startTime, endTime)}`
  );
}

export async function fetchAnalystActivityReport(
  startTime?: string,
  endTime?: string
): Promise<AnalystActivityReport> {
  return apiClient.get<AnalystActivityReport>(
    `/api/v1/reports/analyst-activity${buildQueryParams(startTime, endTime)}`
  );
}

export async function fetchAuditReport(
  startTime?: string,
  endTime?: string
): Promise<SecurityAuditReport> {
  return apiClient.get<SecurityAuditReport>(
    `/api/v1/reports/audit${buildQueryParams(startTime, endTime)}`
  );
}

export async function fetchComplianceReport(
  startTime?: string,
  endTime?: string
): Promise<ComplianceEvidenceReport> {
  return apiClient.get<ComplianceEvidenceReport>(
    `/api/v1/reports/compliance${buildQueryParams(startTime, endTime)}`
  );
}

export async function downloadReport(
  type: ReportType,
  format: ReportExportFormat,
  startTime?: string,
  endTime?: string
): Promise<void> {
  const params = new URLSearchParams();
  params.append('type', type);
  params.append('format', format);
  if (startTime) params.append('start_time', startTime);
  if (endTime) params.append('end_time', endTime);

  const url = `/api/v1/reports/export?${params.toString()}`;
  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
    },
  });

  if (!response.ok) {
    let errorMsg = `Export failed with HTTP ${response.status}`;
    try {
      const errJson = await response.json();
      errorMsg = errJson.detail?.message || errJson.message || errorMsg;
    } catch {
      // ignore json parse error
    }
    throw new Error(errorMsg);
  }

  // Extract filename from header or fallback
  const disposition = response.headers.get('content-disposition');
  let filename = `sentinelforge-${type}.${format}`;
  if (disposition && disposition.includes('filename=')) {
    const match = disposition.match(/filename="?([^";]+)"?/);
    if (match && match[1]) {
      filename = match[1];
    }
  }

  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(downloadUrl);
}
