'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  FileCode2,
  Search,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  Play,
  Lock,
} from 'lucide-react';
import { DetectionRule, RuleSeverity, RuleStatus } from '@/types/detection_rule';
import { PaginatedList } from '@/types/api';
import { apiClient } from '@/lib/api/client';
import { useAuth } from '@/lib/auth/context';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Modal } from '@/components/ui/Modal';
import { Table, Column } from '@/components/ui/Table';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { formatDate } from '@/lib/utils';

export default function DetectionRulesPage() {
  const { hasPermission } = useAuth();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchRules = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('limit', '50');
      if (statusFilter) params.set('status', statusFilter);
      if (severityFilter) params.set('severity', severityFilter);

      const data = await apiClient.get<PaginatedList<DetectionRule>>(
        `/api/v1/detection-rules?${params.toString()}`
      );
      setRules(data.items || []);
      setTotal(data.total || 0);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load detection rules.'));
    } finally {
      setIsLoading(false);
    }
  }, [page, statusFilter, severityFilter]);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const filteredRules = rules.filter((r) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      r.rule_id.toLowerCase().includes(q) ||
      r.name.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q)
    );
  });

  const columns: Column<DetectionRule>[] = [
    {
      header: 'Severity',
      accessorKey: 'severity',
      className: 'w-28',
      cell: (item) => <Badge variant="severity" severity={item.severity} />,
    },
    {
      header: 'Rule Identifier & Name',
      cell: (item) => (
        <div className="flex flex-col font-mono">
          <span className="font-semibold text-slate-100 hover:text-blue-400">
            {item.name}
          </span>
          <span className="text-[11px] text-slate-400">ID: {item.rule_id}</span>
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
      header: 'Version',
      accessorKey: 'current_version',
      className: 'w-24 font-mono text-center text-xs',
      cell: (item) => (
        <span className="inline-flex items-center gap-1 text-slate-300 font-semibold bg-surface-100 px-2 py-0.5 rounded border border-slate-700">
          <Lock className="w-2.5 h-2.5 text-slate-400" />
          v{item.current_version}
        </span>
      ),
    },
    {
      header: 'Created At',
      accessorKey: 'created_at',
      className: 'w-36 font-mono text-slate-400 text-xs',
      cell: (item) => formatDate(item.created_at),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100">
            Detection Engineering & Rule Catalog
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Immutable versioned detection rules, criteria logic and lifecycle activations
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={fetchRules}
            isLoading={isLoading}
            className="text-xs font-mono gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <ErrorCard error={error} onRetry={fetchRules} />

      {/* Filter Toolbar */}
      <div className="p-3 bg-surface-200 border border-slate-800 rounded-lg flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[300px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search rule ID or name..."
              className="w-full pl-8 pr-3 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="">All Statuses</option>
            <option value="ACTIVE">Active</option>
            <option value="DRAFT">Draft</option>
            <option value="DISABLED">Disabled</option>
            <option value="DEPRECATED">Deprecated</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-slate-200 font-semibold">{filteredRules.length}</span> of{' '}
          <span className="text-slate-200 font-semibold">{total}</span> rules
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
          data={filteredRules}
          keyExtractor={(item) => item.id}
          onRowClick={(item) => setSelectedRule(item)}
          emptyMessage="No detection rules found matching criteria."
        />
      )}

      {/* Rule Definition Inspector Modal */}
      {selectedRule && (
        <Modal
          isOpen={!!selectedRule}
          onClose={() => setSelectedRule(null)}
          title={`Detection Rule: ${selectedRule.name}`}
          description={`Rule ID: ${selectedRule.rule_id} • Immutable Version v${selectedRule.current_version}`}
          maxWidth="2xl"
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 bg-surface-300 rounded border border-slate-700/80">
              <div>
                <span className="text-slate-500 block text-[10px]">Severity</span>
                <Badge variant="severity" severity={selectedRule.severity} />
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Lifecycle Status</span>
                <Badge variant="status" status={selectedRule.status} dot />
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Version</span>
                <span className="text-slate-200 font-semibold">v{selectedRule.current_version} (Locked)</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Created At</span>
                <span className="text-slate-300">{formatDate(selectedRule.created_at)}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-semibold mb-1 block">Description</span>
              <p className="text-slate-300 p-2.5 bg-surface-300/40 rounded border border-slate-800">
                {selectedRule.description || 'No description provided.'}
              </p>
            </div>

            <div>
              <span className="text-slate-400 font-semibold mb-1 block">
                Rule Evaluation Criteria (Immutable Schema)
              </span>
              <pre className="p-3 bg-surface-400/90 border border-slate-800 rounded text-blue-300 overflow-x-auto max-h-72 text-[11px] leading-relaxed">
                {JSON.stringify(selectedRule.criteria, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <Button variant="secondary" onClick={() => setSelectedRule(null)}>
                Close Rule Inspector
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
