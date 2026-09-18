'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  BarChart3,
  Calendar,
  Download,
  ShieldCheck,
  AlertTriangle,
  Clock,
  FileSpreadsheet,
  FileJson,
  Layers,
  Activity,
  AlertOctagon,
  FileCode2,
  BookOpen,
  Lock,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '@/lib/auth/context';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { EmptyState } from '@/components/ui/EmptyState';
import { Table, Column } from '@/components/ui/Table';
import {
  OperationsSummaryReport,
  AlertPerformanceReport,
  IncidentReport,
  DetectionReport,
  SLAReport,
  ThreatIntelReport,
  AnalystActivityReport,
  SecurityAuditReport,
  ComplianceEvidenceReport,
  ReportType,
  DetectionRuleEffectivenessItem,
  SLABreachItem,
  ComplianceControlEvidenceItem,
  AnalystActivityItem,
} from '@/types/reports';
import {
  fetchSummaryReport,
  fetchAlertsReport,
  fetchIncidentsReport,
  fetchDetectionsReport,
  fetchSLAReport,
  fetchThreatIntelReport,
  fetchAnalystActivityReport,
  fetchAuditReport,
  fetchComplianceReport,
  downloadReport,
} from '@/lib/api/reports';
import { formatDate } from '@/lib/utils';

type PresetType = '24h' | '7d' | '30d' | '90d' | 'custom';

export default function SecurityReportsPage() {
  const { hasPermission } = useAuth();
  const canExport = hasPermission('reports.export');
  const canAudit = hasPermission('reports.audit');

  // Time range state
  const [preset, setPreset] = useState<PresetType>('30d');
  const [customStart, setCustomStart] = useState<string>('');
  const [customEnd, setCustomEnd] = useState<string>('');
  const [activeTab, setActiveTab] = useState<ReportType>('summary');

  // Data states
  const [summaryData, setSummaryData] = useState<OperationsSummaryReport | null>(null);
  const [alertsData, setAlertsData] = useState<AlertPerformanceReport | null>(null);
  const [incidentsData, setIncidentsData] = useState<IncidentReport | null>(null);
  const [detectionsData, setDetectionsData] = useState<DetectionReport | null>(null);
  const [slaData, setSlaData] = useState<SLAReport | null>(null);
  const [intelData, setIntelData] = useState<ThreatIntelReport | null>(null);
  const [analystData, setAnalystData] = useState<AnalystActivityReport | null>(null);
  const [auditData, setAuditData] = useState<SecurityAuditReport | null>(null);
  const [complianceData, setComplianceData] = useState<ComplianceEvidenceReport | null>(null);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  // Compute UTC boundaries
  const getTimeBounds = useCallback((): { start?: string; end?: string } => {
    const now = new Date();
    if (preset === '24h') {
      const start = new Date(now.getTime() - 24 * 3600 * 1000);
      return { start: start.toISOString(), end: now.toISOString() };
    }
    if (preset === '7d') {
      const start = new Date(now.getTime() - 7 * 86400 * 1000);
      return { start: start.toISOString(), end: now.toISOString() };
    }
    if (preset === '30d') {
      const start = new Date(now.getTime() - 30 * 86400 * 1000);
      return { start: start.toISOString(), end: now.toISOString() };
    }
    if (preset === '90d') {
      const start = new Date(now.getTime() - 90 * 86400 * 1000);
      return { start: start.toISOString(), end: now.toISOString() };
    }
    if (preset === 'custom') {
      if (!customStart || !customEnd) return {};
      const s = new Date(customStart);
      const e = new Date(customEnd);
      return { start: s.toISOString(), end: e.toISOString() };
    }
    return {};
  }, [preset, customStart, customEnd]);

  // Load report data for currently active tab
  const loadActiveReport = useCallback(async () => {
    const bounds = getTimeBounds();

    if (preset === 'custom') {
      if (!bounds.start || !bounds.end) {
        setValidationError('Both start and end dates are required for custom range.');
        return;
      }
      const s = new Date(bounds.start).getTime();
      const e = new Date(bounds.end).getTime();
      if (s >= e) {
        setValidationError('Start date must be strictly before end date.');
        return;
      }
      if ((e - s) / 1000 > 365 * 86400) {
        setValidationError('Selected time range cannot exceed 365 days.');
        return;
      }
    }

    setValidationError(null);
    setIsLoading(true);
    setError(null);

    try {
      if (activeTab === 'summary') {
        const res = await fetchSummaryReport(bounds.start, bounds.end);
        setSummaryData(res);
      } else if (activeTab === 'alerts') {
        const res = await fetchAlertsReport(bounds.start, bounds.end);
        setAlertsData(res);
      } else if (activeTab === 'incidents') {
        const res = await fetchIncidentsReport(bounds.start, bounds.end);
        setIncidentsData(res);
      } else if (activeTab === 'detections') {
        const res = await fetchDetectionsReport(bounds.start, bounds.end);
        setDetectionsData(res);
      } else if (activeTab === 'sla') {
        const res = await fetchSLAReport(bounds.start, bounds.end);
        setSlaData(res);
      } else if (activeTab === 'threat-intelligence') {
        const res = await fetchThreatIntelReport(bounds.start, bounds.end);
        setIntelData(res);
      } else if (activeTab === 'compliance') {
        const res = await fetchComplianceReport(bounds.start, bounds.end);
        setComplianceData(res);
      } else if (activeTab === 'analyst-activity') {
        if (canAudit) {
          const res = await fetchAnalystActivityReport(bounds.start, bounds.end);
          setAnalystData(res);
        }
      } else if (activeTab === 'audit') {
        if (canAudit) {
          const res = await fetchAuditReport(bounds.start, bounds.end);
          setAuditData(res);
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load report data.'));
    } finally {
      setIsLoading(false);
    }
  }, [activeTab, getTimeBounds, preset, canAudit]);

  useEffect(() => {
    loadActiveReport();
  }, [loadActiveReport]);

  const handleExport = async (format: 'csv' | 'json') => {
    if (!canExport) return;
    setIsExporting(true);
    try {
      const bounds = getTimeBounds();
      await downloadReport(activeTab, format, bounds.start, bounds.end);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Export failed.');
    } finally {
      setIsExporting(false);
    }
  };

  const formatSeconds = (sec: number | null): string => {
    if (sec === null || sec === undefined) return 'N/A';
    if (sec < 60) return `${Math.round(sec)}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
    const hours = Math.floor(sec / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    return `${hours}h ${mins}m`;
  };

  const tabs: { id: ReportType; label: string; icon: React.ComponentType<{ className?: string }>; requiresAudit?: boolean }[] = [
    { id: 'summary', label: 'Operations Summary', icon: Layers },
    { id: 'alerts', label: 'Alert Lifecycle', icon: Activity },
    { id: 'incidents', label: 'Incident Response', icon: AlertOctagon },
    { id: 'detections', label: 'Detection Rules', icon: FileCode2 },
    { id: 'sla', label: 'SLA Performance', icon: Clock },
    { id: 'threat-intelligence', label: 'Threat Intelligence', icon: BookOpen },
    { id: 'compliance', label: 'Compliance Evidence', icon: ShieldCheck },
    { id: 'analyst-activity', label: 'Analyst Operations', icon: Activity, requiresAudit: true },
    { id: 'audit', label: 'Security Audit', icon: Lock, requiresAudit: true },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <BarChart3 className="w-6 h-6 text-blue-400" />
            Security Reporting & Operational Metrics
          </h1>
          <p className="text-sm text-slate-400 font-mono mt-1">
            Authoritative, auditable operational metrics derived strictly from persisted telemetry.
          </p>
        </div>

        {/* Global Export Controls */}
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleExport('csv')}
            disabled={!canExport || isExporting || isLoading}
            title={!canExport ? 'Permission reports.export required' : 'Export current report as RFC-4180 CSV'}
            className="flex items-center gap-1.5"
          >
            <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
            Export CSV
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleExport('json')}
            disabled={!canExport || isExporting || isLoading}
            title={!canExport ? 'Permission reports.export required' : 'Export current report as structured JSON'}
            className="flex items-center gap-1.5"
          >
            <FileJson className="w-4 h-4 text-blue-400" />
            Export JSON
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={loadActiveReport}
            disabled={isLoading}
            className="px-2.5"
            title="Refresh current report"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </div>

      {/* Time Range Filter Bar */}
      <Card className="p-4 bg-surface-300 border-slate-800">
        <div className="flex flex-wrap items-center justify-between gap-4">
          {/* Preset Buttons */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-xs font-mono text-slate-400 mr-2 flex items-center gap-1">
              <Calendar className="w-3.5 h-3.5 text-blue-400" /> Range:
            </span>
            {(['24h', '7d', '30d', '90d', 'custom'] as PresetType[]).map((p) => (
              <button
                key={p}
                onClick={() => setPreset(p)}
                className={`px-3 py-1.5 rounded text-xs font-mono transition-colors ${
                  preset === p
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'bg-surface-400 text-slate-300 hover:bg-slate-700'
                }`}
              >
                {p === '24h' && 'Last 24 Hours'}
                {p === '7d' && 'Last 7 Days'}
                {p === '30d' && 'Last 30 Days'}
                {p === '90d' && 'Last 90 Days'}
                {p === 'custom' && 'Custom Range'}
              </button>
            ))}
          </div>

          {/* UTC Status Indicator */}
          <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Timezone: Timezone-Aware UTC</span>
          </div>
        </div>

        {/* Custom Range Inputs */}
        {preset === 'custom' && (
          <div className="mt-4 pt-4 border-t border-slate-800 flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <label className="text-xs font-mono text-slate-400">Start (UTC):</label>
              <input
                type="datetime-local"
                value={customStart}
                onChange={(e) => setCustomStart(e.target.value)}
                className="bg-surface-400 border border-slate-700 rounded px-2.5 py-1 text-xs text-slate-100 font-mono focus:border-blue-500 focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs font-mono text-slate-400">End (UTC):</label>
              <input
                type="datetime-local"
                value={customEnd}
                onChange={(e) => setCustomEnd(e.target.value)}
                className="bg-surface-400 border border-slate-700 rounded px-2.5 py-1 text-xs text-slate-100 font-mono focus:border-blue-500 focus:outline-none"
              />
            </div>
            <Button size="sm" variant="primary" onClick={loadActiveReport}>
              Apply Custom Window
            </Button>
          </div>
        )}

        {validationError && (
          <div className="mt-3 text-xs font-mono text-rose-400 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            {validationError}
          </div>
        )}
      </Card>

      {/* Category Tabs */}
      <div className="flex items-center gap-1 border-b border-slate-800 overflow-x-auto pb-1 select-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isRestricted = tab.requiresAudit && !canAudit;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono rounded-t-lg transition-colors whitespace-nowrap border-b-2 ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400 bg-surface-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface-300/40'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
              {isRestricted && (
                <span title="Requires reports.audit permission">
                  <Lock className="w-3 h-3 text-amber-400" />
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Report Content Panel */}
      {error ? (
        <ErrorCard error={error} onRetry={loadActiveReport} />
      ) : isLoading ? (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
          <Skeleton className="h-64" />
        </div>
      ) : (
        <div>
          {/* TAB 1: OPERATIONS SUMMARY */}
          {activeTab === 'summary' && summaryData && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs font-mono text-slate-400 uppercase">Total Alerts Generated</span>
                  <div className="text-2xl font-bold font-mono text-slate-100 mt-1">{summaryData.total_alerts}</div>
                  <span className="text-[10px] font-mono text-slate-500 mt-1 block">In reporting window</span>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs font-mono text-slate-400 uppercase">Acknowledged</span>
                  <div className="text-2xl font-bold font-mono text-blue-400 mt-1">{summaryData.acknowledged_count}</div>
                  <span className="text-[10px] font-mono text-slate-500 mt-1 block">
                    {summaryData.total_alerts > 0
                      ? `${Math.round((summaryData.acknowledged_count / summaryData.total_alerts) * 100)}% acknowledged`
                      : '0%'}
                  </span>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs font-mono text-slate-400 uppercase">Resolved Cases</span>
                  <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{summaryData.resolved_count}</div>
                  <span className="text-[10px] font-mono text-slate-500 mt-1 block">
                    {summaryData.closed_count} closed
                  </span>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs font-mono text-slate-400 uppercase">Active Catalog</span>
                  <div className="text-2xl font-bold font-mono text-indigo-400 mt-1">
                    {summaryData.total_active_rules} Rules
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 mt-1 block">
                    {summaryData.total_active_indicators} active indicators
                  </span>
                </Card>
              </div>

              {/* Severity & Status Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card className="p-5 bg-surface-300 border-slate-800">
                  <h3 className="text-sm font-semibold font-mono text-slate-200 mb-4">Alert Severity Distribution</h3>
                  <div className="space-y-3 font-mono text-xs">
                    {Object.entries(summaryData.alerts_by_severity).map(([sev, count]) => (
                      <div key={sev} className="flex items-center justify-between">
                        <Badge variant="severity" severity={sev} />
                        <div className="flex items-center gap-3">
                          <div className="w-32 bg-slate-800 rounded-full h-2 overflow-hidden">
                            <div
                              className="bg-blue-500 h-full rounded-full"
                              style={{
                                width: summaryData.total_alerts > 0 ? `${(count / summaryData.total_alerts) * 100}%` : '0%',
                              }}
                            />
                          </div>
                          <span className="text-slate-200 w-8 text-right">{count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>

                <Card className="p-5 bg-surface-300 border-slate-800">
                  <h3 className="text-sm font-semibold font-mono text-slate-200 mb-4">Lifecycle Status Breakdown</h3>
                  <div className="space-y-3 font-mono text-xs">
                    {Object.entries(summaryData.alerts_by_status).map(([st, count]) => (
                      <div key={st} className="flex items-center justify-between">
                        <span className="text-slate-300">{st}</span>
                        <div className="flex items-center gap-3">
                          <div className="w-32 bg-slate-800 rounded-full h-2 overflow-hidden">
                            <div
                              className="bg-indigo-500 h-full rounded-full"
                              style={{
                                width: summaryData.total_alerts > 0 ? `${(count / summaryData.total_alerts) * 100}%` : '0%',
                              }}
                            />
                          </div>
                          <span className="text-slate-200 w-8 text-right">{count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            </div>
          )}

          {/* TAB 2: ALERT LIFECYCLE METRICS */}
          {activeTab === 'alerts' && alertsData && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                  { title: 'Time to Acknowledge', metric: alertsData.lifecycle.time_to_acknowledge },
                  { title: 'Time to Assignment', metric: alertsData.lifecycle.time_to_assign },
                  { title: 'Time to Resolution', metric: alertsData.lifecycle.time_to_resolve },
                  { title: 'Time to Closure', metric: alertsData.lifecycle.time_to_close },
                ].map((item) => (
                  <Card key={item.title} className="p-4 bg-surface-300 border-slate-800 font-mono">
                    <span className="text-xs text-slate-400 uppercase">{item.title}</span>
                    <div className="mt-2 flex items-baseline gap-2">
                      <span className="text-xl font-bold text-slate-100">
                        {item.metric.sample_count > 0 ? formatSeconds(item.metric.mean_seconds) : 'N/A'}
                      </span>
                      <span className="text-xs text-slate-400">
                        {item.metric.sample_count > 0 ? 'avg' : '(No samples)'}
                      </span>
                    </div>
                    {item.metric.sample_count > 0 ? (
                      <div className="mt-3 pt-3 border-t border-slate-800 text-[11px] text-slate-400 space-y-1">
                        <div className="flex justify-between">
                          <span>Median:</span>
                          <span className="text-slate-200">{formatSeconds(item.metric.median_seconds)}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Range:</span>
                          <span className="text-slate-200">
                            {formatSeconds(item.metric.min_seconds)} – {formatSeconds(item.metric.max_seconds)}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span>Sample Count:</span>
                          <span className="text-slate-200">{item.metric.sample_count}</span>
                        </div>
                      </div>
                    ) : (
                      <div className="mt-3 pt-3 border-t border-slate-800 text-[10px] text-slate-500">
                        Zero completed events in this window. Not converted to 0s.
                      </div>
                    )}
                  </Card>
                ))}
              </div>

              {/* Backlog State */}
              <Card className="p-5 bg-surface-300 border-slate-800">
                <h3 className="text-sm font-semibold font-mono text-slate-200 mb-3">Triage Backlog State (Uncompleted)</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs">
                  <div className="p-3 bg-surface-400 rounded border border-slate-800">
                    <span className="text-slate-400 block">Unacknowledged</span>
                    <span className="text-lg font-bold text-amber-400">{alertsData.lifecycle.unacknowledged_count}</span>
                  </div>
                  <div className="p-3 bg-surface-400 rounded border border-slate-800">
                    <span className="text-slate-400 block">Unassigned</span>
                    <span className="text-lg font-bold text-slate-200">{alertsData.lifecycle.unassigned_count}</span>
                  </div>
                  <div className="p-3 bg-surface-400 rounded border border-slate-800">
                    <span className="text-slate-400 block">Unresolved</span>
                    <span className="text-lg font-bold text-blue-400">{alertsData.lifecycle.unresolved_count}</span>
                  </div>
                  <div className="p-3 bg-surface-400 rounded border border-slate-800">
                    <span className="text-slate-400 block">Unclosed</span>
                    <span className="text-lg font-bold text-slate-300">{alertsData.lifecycle.unclosed_count}</span>
                  </div>
                </div>
              </Card>
            </div>
          )}

          {/* TAB 3: INCIDENT RESPONSE */}
          {activeTab === 'incidents' && incidentsData && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Incidents in Window</span>
                  <div className="text-2xl font-bold text-slate-100 mt-1">{incidentsData.total_incidents}</div>
                  <span className="text-[11px] text-slate-500 mt-1 block">
                    {incidentsData.linked_alerts_count} correlated alerts
                  </span>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Mean Case Duration</span>
                  <div className="text-2xl font-bold text-emerald-400 mt-1">
                    {formatSeconds(incidentsData.duration_metrics.mean_seconds)}
                  </div>
                  <span className="text-[11px] text-slate-500 mt-1 block">
                    Based on {incidentsData.duration_metrics.sample_count} resolved incidents
                  </span>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Median Duration</span>
                  <div className="text-2xl font-bold text-blue-400 mt-1">
                    {formatSeconds(incidentsData.duration_metrics.median_seconds)}
                  </div>
                  <span className="text-[11px] text-slate-500 mt-1 block">Midpoint of resolved cases</span>
                </Card>
              </div>

              {/* Resolution breakdown */}
              <Card className="p-5 bg-surface-300 border-slate-800 font-mono">
                <h3 className="text-sm font-semibold text-slate-200 mb-4">Resolution Outcomes</h3>
                <div className="space-y-3 text-xs">
                  {Object.entries(incidentsData.resolution_breakdown).map(([cat, count]) => (
                    <div key={cat} className="flex items-center justify-between">
                      <span className="text-slate-300">{cat}</span>
                      <span className="text-slate-100 font-bold">{count}</span>
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          )}

          {/* TAB 4: DETECTION ENGINEERING */}
          {activeTab === 'detections' && detectionsData && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Active Rules</span>
                  <div className="text-2xl font-bold text-emerald-400 mt-1">{detectionsData.total_active_rules}</div>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Draft Rules</span>
                  <div className="text-2xl font-bold text-blue-400 mt-1">{detectionsData.total_draft_rules}</div>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Disabled</span>
                  <div className="text-2xl font-bold text-amber-400 mt-1">{detectionsData.total_disabled_rules}</div>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Deprecated</span>
                  <div className="text-2xl font-bold text-slate-400 mt-1">{detectionsData.total_deprecated_rules}</div>
                </Card>
              </div>

              <Card className="bg-surface-300 border-slate-800 overflow-hidden font-mono">
                <div className="p-4 border-b border-slate-800">
                  <h3 className="text-sm font-semibold text-slate-200">
                    Rule Activity Breakdown (Exact ID & Version Provenance)
                  </h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-surface-400 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-3">Rule ID</th>
                        <th className="p-3">Rule Name</th>
                        <th className="p-3">Version</th>
                        <th className="p-3">Status</th>
                        <th className="p-3 text-right">Alert Count</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-300">
                      {detectionsData.rule_effectiveness.map((item, idx) => (
                        <tr key={`${item.rule_id}-${item.rule_version}-${idx}`} className="hover:bg-slate-800/50">
                          <td className="p-3 font-semibold text-blue-400">{item.rule_id}</td>
                          <td className="p-3 text-slate-100">{item.rule_name}</td>
                          <td className="p-3">v{item.rule_version}</td>
                          <td className="p-3">
                            <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                              {item.current_status}
                            </span>
                          </td>
                          <td className="p-3 text-right font-bold text-slate-100">{item.alert_count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </div>
          )}

          {/* TAB 5: SLA PERFORMANCE */}
          {activeTab === 'sla' && slaData && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Triage Breach Rate</span>
                  <div className="text-3xl font-bold mt-1 text-rose-400">
                    {slaData.breach_rate_percentage}%
                  </div>
                  <span className="text-[11px] text-slate-400 mt-1 block">
                    {slaData.sla_breached_count} of {slaData.applicable_alerts} applicable alerts
                  </span>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Breached Alerts</span>
                  <div className="text-3xl font-bold text-rose-500 mt-1">{slaData.sla_breached_count}</div>
                  <span className="text-[11px] text-slate-500 mt-1 block">Exceeded 24h triage threshold</span>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Applicable Denominator</span>
                  <div className="text-3xl font-bold text-slate-100 mt-1">{slaData.applicable_alerts}</div>
                  <span className="text-[11px] text-slate-500 mt-1 block">CRITICAL & HIGH alerts in window</span>
                </Card>
              </div>

              <Card className="bg-surface-300 border-slate-800 overflow-hidden font-mono">
                <div className="p-4 border-b border-slate-800">
                  <h3 className="text-sm font-semibold text-slate-200">Breached Alert Ledger</h3>
                </div>
                {slaData.breached_alerts.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-400">
                    Zero SLA breaches detected in the selected time window.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-surface-400 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="p-3">Severity</th>
                          <th className="p-3">Title</th>
                          <th className="p-3">Created</th>
                          <th className="p-3">Triage Delay</th>
                          <th className="p-3">Assigned To</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 text-slate-300">
                        {slaData.breached_alerts.map((item) => (
                          <tr key={item.alert_id} className="hover:bg-slate-800/50">
                            <td className="p-3">
                              <Badge variant="severity" severity={item.severity} />
                            </td>
                            <td className="p-3 text-slate-100">{item.title}</td>
                            <td className="p-3 text-slate-400">{formatDate(item.created_at)}</td>
                            <td className="p-3 text-rose-400 font-bold">{formatSeconds(item.triage_delay_seconds)}</td>
                            <td className="p-3 text-slate-400">{item.assigned_to || 'Unassigned'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </div>
          )}

          {/* TAB 6: THREAT INTELLIGENCE */}
          {activeTab === 'threat-intelligence' && intelData && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono">
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Total Indicators</span>
                  <div className="text-2xl font-bold text-slate-100 mt-1">{intelData.total_indicators}</div>
                </Card>
                <Card className="p-4 bg-surface-300 border-slate-800">
                  <span className="text-xs text-slate-400 uppercase">Sightings in Period</span>
                  <div className="text-2xl font-bold text-emerald-400 mt-1">{intelData.total_sightings_in_period}</div>
                </Card>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
                <Card className="p-5 bg-surface-300 border-slate-800">
                  <h3 className="text-sm font-semibold text-slate-200 mb-4">Indicators by Type</h3>
                  <div className="space-y-2">
                    {Object.entries(intelData.indicators_by_type).map(([t, count]) => (
                      <div key={t} className="flex justify-between py-1 border-b border-slate-800/50">
                        <span className="text-slate-400">{t}</span>
                        <span className="text-slate-100 font-bold">{count}</span>
                      </div>
                    ))}
                  </div>
                </Card>
                <Card className="p-5 bg-surface-300 border-slate-800">
                  <h3 className="text-sm font-semibold text-slate-200 mb-4">Indicators by Status</h3>
                  <div className="space-y-2">
                    {Object.entries(intelData.indicators_by_status).map(([s, count]) => (
                      <div key={s} className="flex justify-between py-1 border-b border-slate-800/50">
                        <span className="text-slate-400">{s}</span>
                        <span className="text-slate-100 font-bold">{count}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            </div>
          )}

          {/* TAB 7: COMPLIANCE CONTROL EVIDENCE */}
          {activeTab === 'compliance' && complianceData && (
            <div className="space-y-6">
              {/* Disclaimer Notice */}
              <div className="p-4 bg-blue-950/40 border border-blue-800/60 rounded-lg text-xs font-mono text-blue-200 flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold block mb-1">Authoritative Audit Evidence Model</span>
                  {complianceData.disclaimer}
                </div>
              </div>

              <Card className="bg-surface-300 border-slate-800 overflow-hidden font-mono">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-surface-400 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-3">Control ID</th>
                        <th className="p-3">Control Name & Description</th>
                        <th className="p-3">Evidence Source</th>
                        <th className="p-3 text-right">Count</th>
                        <th className="p-3 text-center">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-300">
                      {complianceData.controls.map((c) => (
                        <tr key={c.control_id} className="hover:bg-slate-800/50">
                          <td className="p-3 font-bold text-blue-400">{c.control_id}</td>
                          <td className="p-3">
                            <div className="font-semibold text-slate-100">{c.control_name}</div>
                            <div className="text-[11px] text-slate-400 mt-0.5">{c.description}</div>
                          </td>
                          <td className="p-3 text-slate-400">{c.evidence_source}</td>
                          <td className="p-3 text-right font-bold text-slate-100">{c.evidence_count}</td>
                          <td className="p-3 text-center">
                            <span
                              className={`px-2.5 py-1 rounded text-[10px] font-bold border ${
                                c.status === 'EVIDENCE_AVAILABLE'
                                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                                  : 'bg-amber-950/60 text-amber-400 border-amber-800'
                              }`}
                            >
                              {c.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </div>
          )}

          {/* TAB 8: ANALYST RECORDED ACTIVITY */}
          {activeTab === 'analyst-activity' && (
            <div>
              {!canAudit ? (
                <div className="p-8 text-center bg-surface-300 border border-slate-800 rounded-lg font-mono text-xs text-slate-400">
                  <Lock className="w-8 h-8 text-amber-400 mx-auto mb-2" />
                  <span className="font-bold text-slate-200 block text-sm">Restricted Security Report</span>
                  Permission <code className="text-amber-400">reports.audit</code> is required to view analyst operational activity.
                </div>
              ) : analystData ? (
                <div className="space-y-6">
                  {/* Non-evaluative disclaimer */}
                  <div className="p-4 bg-amber-950/40 border border-amber-800/60 rounded-lg text-xs font-mono text-amber-200 flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold block mb-1">Operational Capacity Review Only</span>
                      {analystData.disclaimer}
                    </div>
                  </div>

                  <Card className="bg-surface-300 border-slate-800 overflow-hidden font-mono">
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs text-left">
                        <thead className="bg-surface-400 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="p-3">Analyst</th>
                            <th className="p-3 text-right">Acknowledged</th>
                            <th className="p-3 text-right">Assigned</th>
                            <th className="p-3 text-right">Resolved</th>
                            <th className="p-3 text-right">Notes</th>
                            <th className="p-3 text-right">Incidents</th>
                            <th className="p-3 text-right">Total Recorded</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800 text-slate-300">
                          {analystData.analysts.map((a) => (
                            <tr key={a.user_id} className="hover:bg-slate-800/50">
                              <td className="p-3 font-semibold text-slate-100">{a.username}</td>
                              <td className="p-3 text-right">{a.alerts_acknowledged}</td>
                              <td className="p-3 text-right">{a.alerts_assigned}</td>
                              <td className="p-3 text-right">{a.alerts_resolved}</td>
                              <td className="p-3 text-right">{a.triage_notes_created}</td>
                              <td className="p-3 text-right">{a.incidents_updated}</td>
                              <td className="p-3 text-right font-bold text-blue-400">{a.total_recorded_actions}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </Card>
                </div>
              ) : null}
            </div>
          )}

          {/* TAB 9: SECURITY AUDIT */}
          {activeTab === 'audit' && (
            <div>
              {!canAudit ? (
                <div className="p-8 text-center bg-surface-300 border border-slate-800 rounded-lg font-mono text-xs text-slate-400">
                  <Lock className="w-8 h-8 text-amber-400 mx-auto mb-2" />
                  <span className="font-bold text-slate-200 block text-sm">Restricted Security Report</span>
                  Permission <code className="text-amber-400">reports.audit</code> is required to inspect security audit telemetry.
                </div>
              ) : auditData ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
                    <Card className="p-4 bg-surface-300 border-slate-800">
                      <span className="text-xs text-slate-400 uppercase">Total Audit Records</span>
                      <div className="text-2xl font-bold text-slate-100 mt-1">{auditData.total_audit_events}</div>
                    </Card>
                    <Card className="p-4 bg-surface-300 border-slate-800">
                      <span className="text-xs text-slate-400 uppercase">Login Successes</span>
                      <div className="text-2xl font-bold text-emerald-400 mt-1">{auditData.login_success_count}</div>
                    </Card>
                    <Card className="p-4 bg-surface-300 border-slate-800">
                      <span className="text-xs text-slate-400 uppercase">Login Failures</span>
                      <div className="text-2xl font-bold text-rose-400 mt-1">{auditData.login_failure_count}</div>
                    </Card>
                  </div>

                  <Card className="p-5 bg-surface-300 border-slate-800 font-mono text-xs">
                    <h3 className="text-sm font-semibold text-slate-200 mb-4">Action Distribution</h3>
                    <div className="space-y-2">
                      {Object.entries(auditData.action_distribution).map(([act, count]) => (
                        <div key={act} className="flex justify-between py-1 border-b border-slate-800/50">
                          <span className="text-slate-300">{act}</span>
                          <span className="text-slate-100 font-bold">{count}</span>
                        </div>
                      ))}
                    </div>
                  </Card>
                </div>
              ) : null}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
