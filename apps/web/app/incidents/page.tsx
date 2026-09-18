'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  AlertOctagon,
  Plus,
  RefreshCw,
  Search,
  Clock,
  UserCheck,
} from 'lucide-react';
import { Incident, IncidentSeverity, IncidentStatus } from '@/types/incident';
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

export default function IncidentsPage() {
  const router = useRouter();
  const { hasPermission } = useAuth();

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  // Create Incident Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>('MEDIUM');
  const [isCreating, setIsCreating] = useState(false);

  const fetchIncidents = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('limit', '50');
      if (statusFilter) params.set('status', statusFilter);
      if (severityFilter) params.set('severity', severityFilter);

      const data = await apiClient.get<PaginatedList<Incident>>(
        `/api/v1/incidents?${params.toString()}`
      );
      setIncidents(data.items || []);
      setTotal(data.total || 0);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load incidents.'));
    } finally {
      setIsLoading(false);
    }
  }, [page, statusFilter, severityFilter]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !newDescription.trim()) return;

    setIsCreating(true);
    setError(null);
    try {
      const created = await apiClient.post<Incident>('/api/v1/incidents', {
        title: newTitle.trim(),
        description: newDescription.trim(),
        severity: newSeverity,
      });
      setShowCreateModal(false);
      setNewTitle('');
      setNewDescription('');
      setNewSeverity('MEDIUM');
      router.push(`/incidents/${created.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to create incident case.'));
    } finally {
      setIsCreating(false);
    }
  };

  const columns: Column<Incident>[] = [
    {
      header: 'Severity',
      accessorKey: 'severity',
      className: 'w-28',
      cell: (item) => <Badge variant="severity" severity={item.severity} />,
    },
    {
      header: 'Incident Case Title',
      accessorKey: 'title',
      cell: (item) => (
        <div className="flex flex-col">
          <span className="font-semibold text-slate-100 hover:text-blue-400 transition-colors">
            {item.title}
          </span>
          <span className="text-[11px] font-mono text-slate-400 truncate max-w-md">
            {item.description}
          </span>
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
      header: 'Lead Analyst',
      className: 'w-36 font-mono text-xs',
      cell: (item) =>
        item.lead_analyst ? (
          <span className="text-slate-300">{item.lead_analyst.username}</span>
        ) : (
          <span className="text-slate-500 italic">Unassigned</span>
        ),
    },
    {
      header: 'Created At',
      accessorKey: 'created_at',
      className: 'w-36 font-mono text-slate-400 text-xs',
      cell: (item) => formatTimeAgo(item.created_at),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100">
            Incident Case Management
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Security incident dossiers, evidence correlation and containment tracking
          </p>
        </div>
        <div className="flex items-center gap-2">
          {hasPermission('incidents.create') && (
            <Button
              size="sm"
              variant="primary"
              onClick={() => setShowCreateModal(true)}
              className="text-xs font-mono gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              New Incident Case
            </Button>
          )}
          <Button
            size="sm"
            variant="secondary"
            onClick={fetchIncidents}
            isLoading={isLoading}
            className="text-xs font-mono gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <ErrorCard error={error} onRetry={fetchIncidents} />

      {/* Filter Toolbar */}
      <div className="p-3 bg-surface-200 border border-slate-800 rounded-lg flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
            <option value="CLOSED">Closed</option>
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
          </select>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-slate-200 font-semibold">{incidents.length}</span> of{' '}
          <span className="text-slate-200 font-semibold">{total}</span> incident cases
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
          data={incidents}
          keyExtractor={(item) => item.id}
          onRowClick={(item) => router.push(`/incidents/${item.id}`)}
          emptyMessage="No incident cases found matching active criteria."
        />
      )}

      {/* Create Incident Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Initialize New Incident Case"
        description="Establish a formal security incident dossier for cross-alert response."
      >
        <form onSubmit={handleCreateIncident} className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Incident Title</label>
            <input
              type="text"
              required
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="e.g. Unauthorized Credential Dumping on Domain Controller"
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Severity Classification</label>
            <select
              value={newSeverity}
              onChange={(e) => setNewSeverity(e.target.value as IncidentSeverity)}
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="CRITICAL">Critical (Immediate containment required)</option>
              <option value="HIGH">High (High business risk)</option>
              <option value="MEDIUM">Medium (Moderate operational concern)</option>
              <option value="LOW">Low (Routine security review)</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Scope & Technical Summary</label>
            <textarea
              rows={3}
              required
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Detail preliminary attack indicators, affected hosts, and containment goals..."
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
              disabled={!newTitle.trim() || !newDescription.trim() || isCreating}
              isLoading={isCreating}
            >
              Create Incident Case
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
