'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  Binary,
  Search,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Code,
  Eye,
} from 'lucide-react';
import { SecurityEvent } from '@/types/event';
import { PaginatedList } from '@/types/api';
import { apiClient } from '@/lib/api/client';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { Table, Column } from '@/components/ui/Table';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { formatDate } from '@/lib/utils';

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [limit] = useState(50);
  const [sourceFilter, setSourceFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchEvents = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('limit', String(limit));
      if (sourceFilter) params.set('source', sourceFilter);
      if (severityFilter) params.set('severity', severityFilter);
      if (eventTypeFilter) params.set('event_type', eventTypeFilter);
      if (searchQuery.trim()) {
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(searchQuery.trim())) {
          params.set('source_ip', searchQuery.trim());
        } else {
          params.set('username', searchQuery.trim());
        }
      }

      const data = await apiClient.get<PaginatedList<SecurityEvent>>(
        `/api/v1/events?${params.toString()}`
      );
      setEvents(data.items || []);
      setTotal(data.total || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load security events.'));
    } finally {
      setIsLoading(false);
    }
  }, [page, limit, sourceFilter, severityFilter, eventTypeFilter, searchQuery]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  const columns: Column<SecurityEvent>[] = [
    {
      header: 'Severity',
      accessorKey: 'severity',
      className: 'w-24',
      cell: (item) => <Badge variant="severity" severity={item.severity} />,
    },
    {
      header: 'Timestamp (UTC)',
      accessorKey: 'timestamp',
      className: 'w-44 font-mono text-slate-400 text-xs',
      cell: (item) => formatDate(item.timestamp),
    },
    {
      header: 'Source / Type',
      cell: (item) => (
        <div className="flex flex-col font-mono text-xs">
          <span className="font-semibold text-slate-200">{item.source}</span>
          <span className="text-[11px] text-slate-400">
            {item.event_type} • {item.action}
          </span>
        </div>
      ),
    },
    {
      header: 'Network Context',
      className: 'w-48 font-mono text-xs text-slate-300',
      cell: (item) => (
        <div className="flex flex-col text-[11px]">
          {item.source_ip && <span>Src: {item.source_ip}</span>}
          {item.destination_ip && <span>Dst: {item.destination_ip}</span>}
          {!item.source_ip && !item.destination_ip && <span className="text-slate-500">—</span>}
        </div>
      ),
    },
    {
      header: 'User',
      accessorKey: 'username',
      className: 'w-28 font-mono text-xs text-slate-300',
      cell: (item) => item.username || '—',
    },
    {
      header: 'Normalization',
      accessorKey: 'normalization_status',
      className: 'w-28 font-mono text-xs',
      cell: (item) => (
        <span
          className={`px-1.5 py-0.5 rounded text-[10px] ${
            item.normalization_status === 'NORMALIZED'
              ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800'
              : 'bg-amber-950/60 text-amber-400 border border-amber-800'
          }`}
        >
          {item.normalization_status}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100">
            Security Event Telemetry
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Normalized security logs, raw sensor payloads and evidentiary audit records
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={fetchEvents}
            isLoading={isLoading}
            className="text-xs font-mono gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <ErrorCard error={error} onRetry={fetchEvents} />

      {/* Filter Toolbar */}
      <div className="p-3 bg-surface-200 border border-slate-800 rounded-lg flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[300px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchEvents()}
              placeholder="Search IP or username..."
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
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-slate-200 font-semibold">{events.length}</span> of{' '}
          <span className="text-slate-200 font-semibold">{total}</span> events
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
          data={events}
          keyExtractor={(item) => item.id}
          onRowClick={(item) => setSelectedEvent(item)}
          emptyMessage="No security events found matching criteria."
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

      {/* Event Details & Raw JSON Payload Inspector Modal */}
      {selectedEvent && (
        <Modal
          isOpen={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
          title="Security Event Evidence Inspector"
          description={`UUID: ${selectedEvent.id}`}
          maxWidth="2xl"
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 bg-surface-300 rounded border border-slate-700/80">
              <div>
                <span className="text-slate-500 block text-[10px]">Source</span>
                <span className="text-slate-200 font-semibold">{selectedEvent.source}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Event Type</span>
                <span className="text-slate-200 font-semibold">{selectedEvent.event_type}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Severity</span>
                <Badge variant="severity" severity={selectedEvent.severity} />
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Ingested At</span>
                <span className="text-slate-300">{formatDate(selectedEvent.ingested_at)}</span>
              </div>
            </div>

            {/* Preserved Verbatim Raw Payload */}
            <div>
              <span className="text-slate-400 font-semibold mb-1 block">
                Preserved Raw Payload (Evidentiary JSON)
              </span>
              <pre className="p-3 bg-surface-400/90 border border-slate-800 rounded text-slate-300 overflow-x-auto max-h-72 text-[11px] leading-relaxed">
                {JSON.stringify(selectedEvent.raw_payload, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <Button variant="secondary" onClick={() => setSelectedEvent(null)}>
                Close Inspector
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
