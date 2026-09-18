'use client';

import React, { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ShieldAlert,
  AlertOctagon,
  FileCode2,
  BookOpen,
  Clock,
  RefreshCw,
  ArrowRight,
  ShieldCheck,
  UserCheck,
} from 'lucide-react';
import { SOCDashboardMetrics } from '@/types/dashboard';
import { apiClient } from '@/lib/api/client';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Table, Column } from '@/components/ui/Table';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { AlertSummary } from '@/types/alert';
import { formatDate, formatTimeAgo } from '@/lib/utils';

export default function DashboardPage() {
  const router = useRouter();
  const [metrics, setMetrics] = useState<SOCDashboardMetrics | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchMetrics = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiClient.get<SOCDashboardMetrics>('/api/v1/dashboard/metrics');
      setMetrics(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load dashboard metrics.'));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMetrics();
  }, [fetchMetrics]);

  const alertColumns: Column<AlertSummary>[] = [
    {
      header: 'Severity',
      accessorKey: 'severity',
      className: 'w-28',
      cell: (item) => <Badge variant="severity" severity={item.severity} />,
    },
    {
      header: 'Alert Title',
      accessorKey: 'title',
      cell: (item) => (
        <div className="flex flex-col">
          <span className="font-semibold text-slate-100 hover:text-blue-400 transition-colors">
            {item.title}
          </span>
          <span className="text-[11px] font-mono text-slate-400">Rule: {item.rule_name}</span>
        </div>
      ),
    },
    {
      header: 'Status',
      accessorKey: 'status',
      className: 'w-32',
      cell: (item) => <Badge variant="status" status={item.status} dot />,
    },
    {
      header: 'Priority',
      accessorKey: 'priority_score',
      className: 'w-20 font-mono text-center',
      cell: (item) => (
        <span
          className={`font-bold ${
            item.priority_score >= 80
              ? 'text-red-400'
              : item.priority_score >= 60
              ? 'text-orange-400'
              : 'text-slate-300'
          }`}
        >
          {item.priority_score}
        </span>
      ),
    },
    {
      header: 'Assignee',
      accessorKey: 'assignee',
      className: 'w-32 font-mono text-xs',
      cell: (item) => (
        item.assignee ? (
          <span className="text-slate-300">{item.assignee.username}</span>
        ) : (
          <span className="text-slate-500 italic">Unassigned</span>
        )
      ),
    },
    {
      header: 'First Seen',
      accessorKey: 'first_seen',
      className: 'w-36 font-mono text-slate-400 text-xs',
      cell: (item) => formatTimeAgo(item.first_seen),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100">
            SOC Operations Dashboard
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time security telemetry, active threat alerts & response readiness
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            size="sm"
            variant="secondary"
            onClick={fetchMetrics}
            isLoading={isLoading}
            className="text-xs font-mono gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
          <Link href="/alerts">
            <Button size="sm" variant="primary" className="text-xs font-mono gap-1.5">
              Triage Workspace
              <ArrowRight className="w-3.5 h-3.5" />
            </Button>
          </Link>
        </div>
      </div>

      <ErrorCard error={error} onRetry={fetchMetrics} />

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Open Alerts */}
        <div className="p-4 rounded-lg bg-surface-200 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Active Alerts</span>
            <ShieldAlert className="w-4 h-4 text-blue-400" />
          </div>
          {isLoading ? (
            <Skeleton className="h-8 w-16" />
          ) : (
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics?.open_alerts_count ?? 0}
            </span>
          )}
          <span className="text-[10px] text-slate-500 font-mono mt-1">
            {metrics?.unacknowledged_alerts_count ?? 0} unacknowledged
          </span>
        </div>

        {/* Critical Alerts */}
        <div className="p-4 rounded-lg bg-surface-200 border border-red-900/40 bg-red-950/10 flex flex-col">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-red-400">Critical</span>
            <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
          </div>
          {isLoading ? (
            <Skeleton className="h-8 w-16" />
          ) : (
            <span className="text-2xl font-bold font-mono text-red-400">
              {metrics?.critical_alerts_count ?? 0}
            </span>
          )}
          <span className="text-[10px] text-red-400/70 font-mono mt-1">Immediate action req.</span>
        </div>

        {/* SLA Breached */}
        <div className="p-4 rounded-lg bg-surface-200 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">SLA Breached</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          {isLoading ? (
            <Skeleton className="h-8 w-16" />
          ) : (
            <span className="text-2xl font-bold font-mono text-amber-400">
              {metrics?.sla_breached_alerts_count ?? 0}
            </span>
          )}
          <span className="text-[10px] text-slate-500 font-mono mt-1">&gt; 24h untriaged</span>
        </div>

        {/* Active Incidents */}
        <div className="p-4 rounded-lg bg-surface-200 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Incidents</span>
            <AlertOctagon className="w-4 h-4 text-orange-400" />
          </div>
          {isLoading ? (
            <Skeleton className="h-8 w-16" />
          ) : (
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics?.open_incidents_count ?? 0}
            </span>
          )}
          <span className="text-[10px] text-slate-500 font-mono mt-1">Open cases</span>
        </div>

        {/* Active Rules */}
        <div className="p-4 rounded-lg bg-surface-200 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Rules Active</span>
            <FileCode2 className="w-4 h-4 text-emerald-400" />
          </div>
          {isLoading ? (
            <Skeleton className="h-8 w-16" />
          ) : (
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics?.active_rules_count ?? 0}
            </span>
          )}
          <span className="text-[10px] text-slate-500 font-mono mt-1">Production engine</span>
        </div>

        {/* Threat IOCs */}
        <div className="p-4 rounded-lg bg-surface-200 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Indicators</span>
            <BookOpen className="w-4 h-4 text-cyan-400" />
          </div>
          {isLoading ? (
            <Skeleton className="h-8 w-16" />
          ) : (
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics?.total_indicators_count ?? 0}
            </span>
          )}
          <span className="text-[10px] text-slate-500 font-mono mt-1">Enriched intelligence</span>
        </div>
      </div>

      {/* Main Content Layout: Priority Alerts Table & Activity Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Priority Alerts Table */}
        <div className="lg:col-span-2">
          <Card
            header={
              <div className="flex items-center justify-between w-full">
                <span className="font-mono text-sm font-semibold text-slate-200">
                  Priority Security Alerts
                </span>
                <Link
                  href="/alerts"
                  className="text-xs text-blue-400 hover:text-blue-300 font-mono flex items-center gap-1"
                >
                  View All Alerts <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
            }
          >
            {isLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
              </div>
            ) : (
              <Table
                columns={alertColumns}
                data={metrics?.recent_alerts || []}
                keyExtractor={(item) => item.id}
                onRowClick={(item) => router.push(`/alerts/${item.id}`)}
                emptyMessage="No pending alerts. System security parameters normal."
              />
            )}
          </Card>
        </div>

        {/* Operational Activity Stream */}
        <div className="lg:col-span-1">
          <Card
            header={
              <div className="flex items-center justify-between w-full">
                <span className="font-mono text-sm font-semibold text-slate-200">
                  Audit Activity Stream
                </span>
                <Link
                  href="/audit"
                  className="text-xs text-blue-400 hover:text-blue-300 font-mono flex items-center gap-1"
                >
                  Audit Trail <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
            }
          >
            {isLoading ? (
              <div className="space-y-3">
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
              </div>
            ) : !metrics?.recent_activity?.length ? (
              <div className="text-center py-8 text-xs font-mono text-slate-500">
                No recent security audit logs recorded.
              </div>
            ) : (
              <div className="space-y-3 divide-y divide-slate-800/60 font-mono">
                {metrics.recent_activity.map((entry) => (
                  <div key={entry.id} className="pt-2.5 first:pt-0 flex flex-col gap-0.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-blue-400 truncate max-w-[200px]">
                        {entry.action}
                      </span>
                      <span className="text-[10px] text-slate-500">
                        {formatTimeAgo(entry.timestamp)}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 flex items-center gap-1">
                      <span>Type:</span>
                      <span className="text-slate-300">{entry.resource_type}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
