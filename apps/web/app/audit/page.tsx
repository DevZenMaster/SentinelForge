'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  History,
  Search,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  User,
} from 'lucide-react';
import { AuditLogEntry } from '@/types/audit';
import { PaginatedList } from '@/types/api';
import { apiClient } from '@/lib/api/client';
import { useAuth } from '@/lib/auth/context';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { Table, Column } from '@/components/ui/Table';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { formatDate } from '@/lib/utils';

export default function AuditPage() {
  const { hasPermission } = useAuth();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState('');
  const [resourceTypeFilter, setResourceTypeFilter] = useState('');
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchLogs = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('limit', '50');
      if (actionFilter.trim()) params.set('action', actionFilter.trim());
      if (resourceTypeFilter.trim()) params.set('resource_type', resourceTypeFilter.trim());

      const data = await apiClient.get<PaginatedList<AuditLogEntry>>(
        `/api/v1/audit/logs?${params.toString()}`
      );
      setLogs(data.items || []);
      setTotal(data.total || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load audit logs.'));
    } finally {
      setIsLoading(false);
    }
  }, [page, actionFilter, resourceTypeFilter]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const columns: Column<AuditLogEntry>[] = [
    {
      header: 'Timestamp (UTC)',
      accessorKey: 'timestamp',
      className: 'w-44 font-mono text-slate-400 text-xs',
      cell: (item) => formatDate(item.timestamp),
    },
    {
      header: 'Action / Operation',
      accessorKey: 'action',
      className: 'w-48 font-mono text-xs font-semibold text-blue-400',
    },
    {
      header: 'Resource Target',
      cell: (item) => (
        <div className="flex flex-col font-mono text-xs">
          <span className="font-semibold text-slate-200 uppercase text-[11px]">
            {item.resource_type}
          </span>
          <span className="text-slate-500 text-[11px] truncate max-w-xs">
            {item.resource_id || '—'}
          </span>
        </div>
      ),
    },
    {
      header: 'Actor / User ID',
      accessorKey: 'actor_user_id',
      className: 'w-40 font-mono text-xs text-slate-400',
      cell: (item) => item.actor_user_id || <span className="text-slate-500 italic">SYSTEM</span>,
    },
    {
      header: 'Source IP',
      accessorKey: 'source_ip',
      className: 'w-32 font-mono text-xs text-slate-400',
      cell: (item) => item.source_ip || '—',
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100">
            Security Audit Trail
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Immutable append-only record of all security events, authentication attempts and triage actions
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={fetchLogs}
            isLoading={isLoading}
            className="text-xs font-mono gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <ErrorCard error={error} onRetry={fetchLogs} />

      {/* Filter Toolbar */}
      <div className="p-3 bg-surface-200 border border-slate-800 rounded-lg flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[300px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchLogs()}
              placeholder="Filter by action (e.g. LOGIN, ALERT_TRIAGE)..."
              className="w-full pl-8 pr-3 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="relative flex-1 max-w-xs">
            <input
              type="text"
              value={resourceTypeFilter}
              onChange={(e) => setResourceTypeFilter(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchLogs()}
              placeholder="Filter by resource type..."
              className="w-full px-3 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-slate-200 font-semibold">{logs.length}</span> of{' '}
          <span className="text-slate-200 font-semibold">{total}</span> audit records
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : (
        <Table
          columns={columns}
          data={logs}
          keyExtractor={(item) => item.id}
          onRowClick={(item) => setSelectedLog(item)}
          emptyMessage="No audit trail records found matching criteria."
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

      {/* Audit Log Detail Modal */}
      {selectedLog && (
        <Modal
          isOpen={!!selectedLog}
          onClose={() => setSelectedLog(null)}
          title="Security Audit Record Detail"
          description={`Log UUID: ${selectedLog.id}`}
          maxWidth="2xl"
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 p-3 bg-surface-300 rounded border border-slate-700/80">
              <div>
                <span className="text-slate-500 block text-[10px]">Action</span>
                <span className="text-blue-400 font-bold">{selectedLog.action}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Resource</span>
                <span className="text-slate-200">
                  {selectedLog.resource_type}: {selectedLog.resource_id}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Timestamp</span>
                <span className="text-slate-300">{formatDate(selectedLog.timestamp)}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Actor User ID</span>
                <span className="text-slate-300">{selectedLog.actor_user_id || 'SYSTEM'}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Client IP</span>
                <span className="text-slate-300">{selectedLog.source_ip || '—'}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Request ID</span>
                <span className="text-slate-300">{selectedLog.request_id || '—'}</span>
              </div>
            </div>

            {selectedLog.old_value && (
              <div>
                <span className="text-slate-400 font-semibold mb-1 block">Previous State</span>
                <pre className="p-3 bg-surface-400/90 border border-slate-800 rounded text-slate-300 overflow-x-auto max-h-48 text-[11px]">
                  {JSON.stringify(selectedLog.old_value, null, 2)}
                </pre>
              </div>
            )}

            {selectedLog.new_value && (
              <div>
                <span className="text-slate-400 font-semibold mb-1 block">Committed State / Changes</span>
                <pre className="p-3 bg-surface-400/90 border border-slate-800 rounded text-emerald-300 overflow-x-auto max-h-48 text-[11px]">
                  {JSON.stringify(selectedLog.new_value, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <Button variant="secondary" onClick={() => setSelectedLog(null)}>
                Close Record
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
