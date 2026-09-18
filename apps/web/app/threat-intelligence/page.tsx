'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  BookOpen,
  Search,
  Plus,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
} from 'lucide-react';
import { PaginatedList } from '@/types/api';
import { apiClient } from '@/lib/api/client';
import { useAuth } from '@/lib/auth/context';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { Table, Column } from '@/components/ui/Table';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { formatDate, formatTimeAgo } from '@/lib/utils';

export interface IndicatorRecord {
  id: string;
  type: string;
  value: string;
  status: string;
  threat_level?: string | null;
  confidence?: number | null;
  sightings_count: number;
  first_seen: string;
  last_seen: string;
}

export default function ThreatIntelligencePage() {
  const { hasPermission } = useAuth();
  const [indicators, setIndicators] = useState<IndicatorRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [typeFilter, setTypeFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  // New Indicator Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newType, setNewType] = useState('ip');
  const [newValue, setNewValue] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchIndicators = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('limit', '50');
      if (typeFilter) params.set('indicator_type', typeFilter);
      if (searchQuery.trim()) params.set('query', searchQuery.trim());

      const data = await apiClient.get<PaginatedList<IndicatorRecord>>(
        `/api/v1/indicators?${params.toString()}`
      );
      setIndicators(data.items || []);
      setTotal(data.total || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load indicators.'));
    } finally {
      setIsLoading(false);
    }
  }, [page, typeFilter, searchQuery]);

  useEffect(() => {
    fetchIndicators();
  }, [fetchIndicators]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue.trim()) return;

    setIsSubmitting(true);
    setError(null);
    try {
      await apiClient.post('/api/v1/indicators', {
        type: newType,
        value: newValue.trim(),
      });
      setShowCreateModal(false);
      setNewValue('');
      fetchIndicators();
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to register indicator.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  const columns: Column<IndicatorRecord>[] = [
    {
      header: 'Type',
      accessorKey: 'type',
      className: 'w-24 font-mono text-xs uppercase',
      cell: (item) => (
        <span className="px-2 py-0.5 rounded bg-surface-100 border border-slate-700 text-slate-300 font-semibold">
          {item.type}
        </span>
      ),
    },
    {
      header: 'Indicator Value / Observable',
      accessorKey: 'value',
      cell: (item) => (
        <span className="font-mono text-xs font-semibold text-slate-100 select-all">
          {item.value}
        </span>
      ),
    },
    {
      header: 'Status',
      accessorKey: 'status',
      className: 'w-28 font-mono text-xs',
      cell: (item) => <Badge variant="status" status={item.status} dot />,
    },
    {
      header: 'Sightings',
      accessorKey: 'sightings_count',
      className: 'w-24 font-mono text-xs text-center',
      cell: (item) => <span className="text-slate-300 font-bold">{item.sightings_count}</span>,
    },
    {
      header: 'First Seen',
      accessorKey: 'first_seen',
      className: 'w-36 font-mono text-slate-400 text-xs',
      cell: (item) => formatDate(item.first_seen),
    },
    {
      header: 'Last Seen',
      accessorKey: 'last_seen',
      className: 'w-36 font-mono text-slate-400 text-xs',
      cell: (item) => formatTimeAgo(item.last_seen),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100">
            Threat Intelligence & IOC Repository
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Structured indicators of compromise, observable attribution and telemetry sightings
          </p>
        </div>
        <div className="flex items-center gap-2">
          {hasPermission('intelligence.create') && (
            <Button
              size="sm"
              variant="primary"
              onClick={() => setShowCreateModal(true)}
              className="text-xs font-mono gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              Register Indicator
            </Button>
          )}
          <Button
            size="sm"
            variant="secondary"
            onClick={fetchIndicators}
            isLoading={isLoading}
            className="text-xs font-mono gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <ErrorCard error={error} onRetry={fetchIndicators} />

      {/* Filter Toolbar */}
      <div className="p-3 bg-surface-200 border border-slate-800 rounded-lg flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[300px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchIndicators()}
              placeholder="Search observable value..."
              className="w-full pl-8 pr-3 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={typeFilter}
            onChange={(e) => {
              setTypeFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="">All Types</option>
            <option value="ipv4">IPv4</option>
            <option value="ipv6">IPv6</option>
            <option value="domain">Domain</option>
            <option value="sha256">SHA-256</option>
            <option value="md5">MD5</option>
            <option value="url">URL</option>
          </select>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-slate-200 font-semibold">{indicators.length}</span> of{' '}
          <span className="text-slate-200 font-semibold">{total}</span> indicators
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
          data={indicators}
          keyExtractor={(item) => item.id}
          emptyMessage="No threat indicators found matching criteria."
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

      {/* Register Indicator Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Register New Threat Indicator"
        description="Add a confirmed malicious observable to SentinelForge threat intelligence."
      >
        <form onSubmit={handleCreate} className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Indicator Type</label>
            <select
              value={newType}
              onChange={(e) => setNewType(e.target.value)}
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="ipv4">IPv4 Address</option>
              <option value="ipv6">IPv6 Address</option>
              <option value="domain">Domain Name / FQDN</option>
              <option value="sha256">SHA-256 Hash</option>
              <option value="md5">MD5 Hash</option>
              <option value="url">URL</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Observable Value</label>
            <input
              type="text"
              required
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              placeholder="e.g. 198.51.100.44 or bad-domain.top"
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <Button variant="ghost" onClick={() => setShowCreateModal(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              disabled={!newValue.trim() || isSubmitting}
              isLoading={isSubmitting}
            >
              Register Indicator
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
