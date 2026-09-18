import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import SecurityReportsPage from '@/app/reports/page';
import { useAuth } from '@/lib/auth/context';
import * as reportsApi from '@/lib/api/reports';

vi.mock('@/lib/auth/context', () => ({
  useAuth: vi.fn(),
}));

vi.mock('@/lib/api/reports', () => ({
  fetchSummaryReport: vi.fn(),
  fetchAlertsReport: vi.fn(),
  fetchIncidentsReport: vi.fn(),
  fetchDetectionsReport: vi.fn(),
  fetchSLAReport: vi.fn(),
  fetchThreatIntelReport: vi.fn(),
  fetchAnalystActivityReport: vi.fn(),
  fetchAuditReport: vi.fn(),
  fetchComplianceReport: vi.fn(),
  downloadReport: vi.fn(),
}));

const mockSummary = {
  time_range: { start_time: '2026-08-19T00:00:00Z', end_time: '2026-09-18T00:00:00Z' },
  total_alerts: 42,
  alerts_by_severity: { CRITICAL: 5, HIGH: 10, MEDIUM: 15, LOW: 10, INFO: 2 },
  alerts_by_status: { OPEN: 8, ACKNOWLEDGED: 12, IN_PROGRESS: 4, SUPPRESSED: 3, RESOLVED: 10, CLOSED: 5 },
  acknowledged_count: 31,
  unacknowledged_count: 11,
  assigned_count: 28,
  unassigned_count: 14,
  suppressed_count: 3,
  resolved_count: 10,
  closed_count: 5,
  open_incident_cases: 3,
  total_active_rules: 12,
  total_active_indicators: 85,
  generated_at: '2026-09-18T10:00:00Z',
};

const mockAlerts = {
  time_range: { start_time: '2026-08-19T00:00:00Z', end_time: '2026-09-18T00:00:00Z' },
  total_alerts: 42,
  alerts_by_severity: { CRITICAL: 5, HIGH: 10, MEDIUM: 15, LOW: 10, INFO: 2 },
  alerts_by_status: { OPEN: 8, ACKNOWLEDGED: 12, IN_PROGRESS: 4, SUPPRESSED: 3, RESOLVED: 10, CLOSED: 5 },
  lifecycle: {
    time_to_acknowledge: { mean_seconds: 450, median_seconds: 420, min_seconds: 60, max_seconds: 900, sample_count: 20 },
    time_to_assign: { mean_seconds: null, median_seconds: null, min_seconds: null, max_seconds: null, sample_count: 0 },
    time_to_resolve: { mean_seconds: 1800, median_seconds: 1750, min_seconds: 500, max_seconds: 3600, sample_count: 10 },
    time_to_close: { mean_seconds: 3600, median_seconds: 3500, min_seconds: 1200, max_seconds: 7200, sample_count: 5 },
    unacknowledged_count: 11,
    unassigned_count: 14,
    unresolved_count: 32,
    unclosed_count: 37,
  },
  generated_at: '2026-09-18T10:00:00Z',
};

const mockSla = {
  time_range: { start_time: '2026-08-19T00:00:00Z', end_time: '2026-09-18T00:00:00Z' },
  sla_breached_count: 3,
  applicable_alerts: 15,
  breach_rate_percentage: 20.0,
  severity_distribution: { CRITICAL: 2, HIGH: 1 },
  breached_alerts: [
    {
      alert_id: 'alt-1',
      title: 'Delayed Critical Attack',
      severity: 'CRITICAL',
      created_at: '2026-09-16T10:00:00Z',
      acknowledged_at: null,
      triage_delay_seconds: 95000,
      assigned_to: null,
    },
  ],
  generated_at: '2026-09-18T10:00:00Z',
};

const mockCompliance = {
  time_range: { start_time: '2026-08-19T00:00:00Z', end_time: '2026-09-18T00:00:00Z' },
  disclaimer: 'SentinelForge provides verifiable operational evidence for audit inspection.',
  controls: [
    {
      control_id: 'CTRL-AUD-01',
      control_name: 'Append-Only Security Audit Logging',
      description: 'Audit logs verification',
      evidence_source: 'audit_logs',
      evidence_period: '2026-08-19 to 2026-09-18',
      evidence_count: 145,
      status: 'EVIDENCE_AVAILABLE' as const,
    },
  ],
  generated_at: '2026-09-18T10:00:00Z',
};

describe('Security Reports Console (Phase 12)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (reportsApi.fetchSummaryReport as any).mockResolvedValue(mockSummary);
    (reportsApi.fetchAlertsReport as any).mockResolvedValue(mockAlerts);
    (reportsApi.fetchSLAReport as any).mockResolvedValue(mockSla);
    (reportsApi.fetchComplianceReport as any).mockResolvedValue(mockCompliance);
  });

  it('renders page header and default 30d operations summary', async () => {
    (useAuth as any).mockReturnValue({
      hasPermission: (perm: string) => ['reports.read', 'reports.export'].includes(perm),
    });

    render(<SecurityReportsPage />);

    expect(screen.getByText('Security Reporting & Operational Metrics')).toBeInTheDocument();
    expect(screen.getByText('Last 30 Days')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('42')).toBeInTheDocument();
      expect(screen.getByText('Total Alerts Generated')).toBeInTheDocument();
      expect(screen.getByText('12 Rules')).toBeInTheDocument();
    });
  });

  it('enforces RBAC export gating: disabled when reports.export is missing', async () => {
    (useAuth as any).mockReturnValue({
      hasPermission: (perm: string) => perm === 'reports.read', // Missing reports.export
    });

    render(<SecurityReportsPage />);

    const exportCsvBtn = screen.getByRole('button', { name: /Export CSV/i });
    expect(exportCsvBtn).toBeDisabled();
    expect(exportCsvBtn).toHaveAttribute('title', 'Permission reports.export required');
  });

  it('handles N/A lifecycle duration states without displaying fake zeros', async () => {
    (useAuth as any).mockReturnValue({
      hasPermission: () => true,
    });

    render(<SecurityReportsPage />);

    // Switch to Alert Lifecycle tab
    const alertsTab = screen.getByRole('button', { name: /Alert Lifecycle/i });
    fireEvent.click(alertsTab);

    await waitFor(() => {
      // Time to Acknowledge has sample_count 20 -> avg formatted
      expect(screen.getByText('7m 30s')).toBeInTheDocument();
      // Time to Assign has sample_count 0 -> N/A rendered
      expect(screen.getByText('N/A')).toBeInTheDocument();
      expect(screen.getByText('Zero completed events in this window. Not converted to 0s.')).toBeInTheDocument();
    });
  });

  it('renders SLA breach report with explicit population denominator', async () => {
    (useAuth as any).mockReturnValue({
      hasPermission: () => true,
    });

    render(<SecurityReportsPage />);

    // Switch to SLA tab
    const slaTab = screen.getByRole('button', { name: /SLA Performance/i });
    fireEvent.click(slaTab);

    await waitFor(() => {
      expect(screen.getByText('20%')).toBeInTheDocument();
      expect(screen.getByText(/3 of 15 applicable alerts/)).toBeInTheDocument();
      expect(screen.getByText('Delayed Critical Attack')).toBeInTheDocument();
    });
  });

  it('renders compliance evidence with factual disclaimers and control status', async () => {
    (useAuth as any).mockReturnValue({
      hasPermission: () => true,
    });

    render(<SecurityReportsPage />);

    // Switch to Compliance tab
    const compTab = screen.getByRole('button', { name: /Compliance Evidence/i });
    fireEvent.click(compTab);

    await waitFor(() => {
      expect(screen.getByText(/Authoritative Audit Evidence Model/)).toBeInTheDocument();
      expect(screen.getByText('CTRL-AUD-01')).toBeInTheDocument();
      expect(screen.getByText('EVIDENCE_AVAILABLE')).toBeInTheDocument();
    });
  });
});
