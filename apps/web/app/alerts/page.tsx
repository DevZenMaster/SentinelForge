'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Clock,
  User as UserIcon,
} from 'lucide-react';
import { AlertSummary, AlertSeverity, AlertStatus } from '@/types/alert';
import { PaginatedList } from '@/types/api';
import { apiClient } from '@/lib/api/client';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Table, Column } from '@/components/ui/Table';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { formatTimeAgo } from '@/lib/utils';

export default function AlertsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(Number(searchParams.get('page')) || 1);
  const [limit, setLimit] = useState(50);
  const [severityFilter, setSeverityFilter] = useState<string>(searchParams.get('severity') || '');
  const [statusFilter, setStatusFilter] = useState<string>(searchParams.get('status') || '');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchAlerts = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('limit', String(limit));
      if (severityFilter) params.set('severity', severityFilter);
      if (statusFilter) params.set('status', statusFilter);
      if (searchQuery.trim()) {
        // Detect IP vs username
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(searchQuery.trim())) {
          params.set('source_ip', searchQuery.trim());
        } else {
          params.set('username', searchQuery.trim());
        }
      }

      const data = await apiClient.get<PaginatedList<AlertSummary>>(
        `/api/v1/alerts?${params.toString()}`
      );
      setAlerts(data.items);
      setTotal(data.total);
      setTotalPages(data.total_pages);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load alerts.'));
    } finally {
      setIsLoading(false);
    }
  }, [page, limit, severityFilter, statusFilter, searchQuery]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const columns: Column<AlertSummary>[] = [
    {
      header: 'Severity',
      accessorKey: 'severity',
      className: 'w-28',
      cell: (item) => <Badge variant="severity" severity={item.severity} />,
    },
    {
      header: 'Alert Title & Rule',
      cell: (item) => (
        <div className="flex flex-col">
          <span className="font-semibold text-slate-100 hover:text-blue-400 transition-colors">
            {item.title}
          </span>
          <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400 mt-0.5">
            <span>Rule: {item.rule_name}</span>
            <span>•</span>
            <span>v{item.rule_version}</span>
            {item.sla_breached && (
              <span className="px-1.5 py-0.2 rounded bg-amber-950/80 text-amber-400 border border-amber-800 text-[10px] uppercase">
                SLA Breached
              </span>
            )}
          </div>
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
      header: 'Entities',
      className: 'w-44 font-mono text-xs text-slate-300',
      cell: (item) => (
        <div className="flex flex-col gap-0.5">
          {item.source_ip && <span>IP: {item.source_ip}</span>}
          {item.username && <span>User: {item.username}</span>}
          {!item.source_ip && !item.username && <span className="text-slate-500">—</span>}
        </div>
      ),
    },
    {
      header: 'Assignee',
      accessorKey: 'assignee',
      className: 'w-32 font-mono text-xs',
      cell: (item) =>
        item.assignee ? (
          <span className="text-slate-300">{item.assignee.username}</span>
        ) : (
          <span className="text-slate-500 italic">Unassigned</span>
        ),
    },
    {
      header: 'First Seen',
      accessorKey: 'first_seen',
      className: 'w-32 font-mono text-slate-400 text-xs',
      cell: (item) => formatTimeAgo(item.first_seen),
    },
  ];

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100">
            Alert Triage Operations
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Active threat detections, prioritization queues and analyst workflow management
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={fetchAlerts}
            isLoading={isLoading}
            className="text-xs font-mono gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <ErrorCard error={error} onRetry={fetchAlerts} />

      {/* Filter Toolbar */}
      <div className="p-3 bg-surface-200 border border-slate-800 rounded-lg flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[300px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchAlerts()}
              placeholder="Filter by IP or username..."
              className="w-full pl-8 pr-3 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="SUPPRESSED">Suppressed</option>
            <option value="RESOLVED">Resolved</option>
            <option value="CLOSED">Closed</option>
          </select>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-slate-200 font-semibold">{alerts.length}</span> of{' '}
          <span className="text-slate-200 font-semibold">{total}</span> alerts
        </div>
      </div>

      {/* Alerts Table */}
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : (
        <Table
          columns={columns}
          data={alerts}
          keyExtractor={(item) => item.id}
          onRowClick={(item) => router.push(`/alerts/${item.id}`)}
          emptyMessage="No security alerts found matching the active filter criteria."
        />
      )}

      {/* Pagination Footer */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2">
          <div className="text-xs font-mono text-slate-400">
            Page {page} of {totalPages}
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={page <= 1 || isLoading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="text-xs font-mono"
            >
              <ChevronLeft className="w-3.5 h-3.5 mr-1" /> Previous
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={page >= totalPages || isLoading}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="text-xs font-mono"
            >
              Next <ChevronRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
