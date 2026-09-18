'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  BellRing,
  RefreshCw,
  RotateCcw,
  XCircle,
  Eye,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Send,
  Layers,
  Activity,
  Filter,
} from 'lucide-react';
import { useAuth } from '@/lib/auth/context';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { EmptyState } from '@/components/ui/EmptyState';
import { Modal } from '@/components/ui/Modal';
import { Table, Column } from '@/components/ui/Table';
import {
  NotificationDelivery,
  DeliveryStatus,
  NotificationEventType,
} from '@/types/notifications';
import { notificationsApi } from '@/lib/api/notifications';
import { formatDate, formatTimeAgo } from '@/lib/utils';

export default function NotificationDeliveriesPage() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission('notifications.read');
  const canRetry = hasPermission('notifications.retry');
  const canCancel = hasPermission('notifications.cancel');

  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<Error | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');

  // Detail Modal
  const [selectedDelivery, setSelectedDelivery] = useState<NotificationDelivery | null>(null);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  const fetchDeliveries = useCallback(async () => {
    if (!canRead) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const params: any = { limit: 100 };
      if (statusFilter !== 'ALL') params.status = statusFilter;
      if (eventTypeFilter !== 'ALL') params.event_type = eventTypeFilter;

      const res: any = await notificationsApi.listDeliveries(params);
      const items = Array.isArray(res) ? res : (res?.data || []);
      setDeliveries(items);
    } catch (err: any) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [canRead, statusFilter, eventTypeFilter]);

  useEffect(() => {
    fetchDeliveries();
  }, [fetchDeliveries]);

  const handleRetry = async (deliveryId: string) => {
    if (!canRetry) return;
    setActionInProgress(deliveryId);
    try {
      await notificationsApi.retryDelivery(deliveryId);
      await fetchDeliveries();
    } catch (err: any) {
      alert(`Retry dispatch failed: ${err.message || err}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleCancel = async (deliveryId: string) => {
    if (!canCancel) return;
    setActionInProgress(deliveryId);
    try {
      await notificationsApi.cancelDelivery(deliveryId);
      await fetchDeliveries();
    } catch (err: any) {
      alert(`Cancellation failed: ${err.message || err}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const getStatusBadge = (status: DeliveryStatus) => {
    switch (status) {
      case 'DELIVERED':
        return <Badge variant="success">DELIVERED</Badge>;
      case 'RETRYING':
        return <Badge variant="warning">RETRYING</Badge>;
      case 'FAILED':
      case 'EXHAUSTED':
        return <Badge variant="danger">{status}</Badge>;
      case 'CANCELLED':
        return <Badge variant="neutral">CANCELLED</Badge>;
      case 'DELIVERING':
      case 'PENDING':
      default:
        return <Badge variant="primary">{status}</Badge>;
    }
  };

  // Metrics
  const deliveredCount = deliveries.filter((d) => d.status === 'DELIVERED').length;
  const inFlightCount = deliveries.filter((d) => d.status === 'PENDING' || d.status === 'DELIVERING' || d.status === 'RETRYING').length;
  const failedCount = deliveries.filter((d) => d.status === 'FAILED' || d.status === 'EXHAUSTED').length;

  const columns: Column<NotificationDelivery>[] = [
    {
      header: 'Timestamp',
      cell: (item) => (
        <div className="font-mono text-xs">
          <div className="text-slate-200">{formatDate(item.created_at)}</div>
          <div className="text-[10px] text-slate-500">{formatTimeAgo(item.created_at)}</div>
        </div>
      ),
    },
    {
      header: 'Security Event',
      cell: (item) => (
        <div className="space-y-1">
          <span className="px-2 py-0.5 rounded bg-blue-950/60 border border-blue-800/80 text-blue-300 font-mono text-[10px]">
            {item.event?.event_type || 'SECURITY_EVENT'}
          </span>
          <div className="text-[11px] text-slate-400 font-mono">
            {item.event?.source_resource_type}:{item.event?.source_resource_id}
          </div>
        </div>
      ),
    },
    {
      header: 'Destination',
      cell: (item) => (
        <div className="space-y-0.5">
          <div className="text-xs font-semibold text-slate-200">
            {item.destination?.name || 'Destination'}
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            {item.destination?.type}
          </div>
        </div>
      ),
    },
    {
      header: 'Status',
      cell: (item) => getStatusBadge(item.status),
    },
    {
      header: 'Attempts',
      cell: (item) => (
        <div className="font-mono text-xs">
          <span className={item.attempt_count >= item.max_attempts ? 'text-amber-400 font-bold' : 'text-slate-300'}>
            {item.attempt_count}
          </span>
          <span className="text-slate-500"> / {item.max_attempts}</span>
          {item.next_retry_at && (
            <div className="text-[10px] text-amber-300 flex items-center gap-1 mt-0.5">
              <Clock className="w-2.5 h-2.5" />
              <span>Retry in {formatTimeAgo(item.next_retry_at)}</span>
            </div>
          )}
        </div>
      ),
    },
    {
      header: 'Response',
      cell: (item) => (
        <div className="font-mono text-xs">
          {item.http_status ? (
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] ${
                item.http_status < 400
                  ? 'bg-emerald-950/60 border border-emerald-800 text-emerald-300'
                  : 'bg-red-950/60 border border-red-800 text-red-300'
              }`}
            >
              HTTP {item.http_status}
            </span>
          ) : (
            <span className="text-slate-500">—</span>
          )}
          {item.latency_ms !== null && item.latency_ms !== undefined && (
            <div className="text-[10px] text-slate-400 mt-0.5">{item.latency_ms} ms</div>
          )}
        </div>
      ),
    },
    {
      header: 'Actions',
      className: 'text-right',
      cell: (item) => (
        <div className="flex items-center justify-end gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSelectedDelivery(item)}
            title="Inspect Details"
            className="p-1.5 text-slate-400 hover:text-slate-200"
          >
            <Eye className="w-3.5 h-3.5" />
          </Button>

          {canRetry && (item.status === 'FAILED' || item.status === 'EXHAUSTED') && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleRetry(item.id)}
              disabled={actionInProgress === item.id}
              className="text-xs px-2 py-1 flex items-center gap-1 text-blue-400 border-blue-800 hover:bg-blue-950/40"
              title="Manual Retry Dispatch"
            >
              <RotateCcw className={`w-3 h-3 ${actionInProgress === item.id ? 'animate-spin' : ''}`} />
              Retry
            </Button>
          )}

          {canCancel && (item.status === 'PENDING' || item.status === 'RETRYING') && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleCancel(item.id)}
              disabled={actionInProgress === item.id}
              className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-950/30"
              title="Cancel Delivery"
            >
              <XCircle className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>
      ),
    },
  ];

  if (!canRead) {
    return (
      <div className="p-8">
        <ErrorCard
          error="Access Denied: You do not possess the 'notifications.read' permission required to inspect delivery attempt logs."
        />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold font-mono tracking-wide text-slate-100">
              Notification Delivery Logs & Auditing
            </h1>
            <Badge variant="outline" className="font-mono text-xs text-blue-400 border-blue-500/30">
              Phase 13
            </Badge>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Authoritative delivery attempt audit trails, idempotency tracking, latency metrics, and manual retry controls.
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={fetchDeliveries}
          disabled={isLoading}
          className="flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh Logs
        </Button>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="p-4 flex items-center gap-4 bg-surface-200 border-slate-800">
          <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono text-slate-100">{deliveredCount}</div>
            <div className="text-xs text-slate-400">Delivered Successfully</div>
          </div>
        </Card>

        <Card className="p-4 flex items-center gap-4 bg-surface-200 border-slate-800">
          <div className="p-3 rounded-lg bg-amber-950/60 border border-amber-800 text-amber-400">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono text-slate-100">{inFlightCount}</div>
            <div className="text-xs text-slate-400">Pending / Retrying</div>
          </div>
        </Card>

        <Card className="p-4 flex items-center gap-4 bg-surface-200 border-slate-800">
          <div className="p-3 rounded-lg bg-red-950/60 border border-red-800 text-red-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono text-slate-100">{failedCount}</div>
            <div className="text-xs text-slate-400">Failed / Exhausted</div>
          </div>
        </Card>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-surface-300 p-3 rounded-lg border border-slate-800">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider mr-1">Status:</span>
          {['ALL', 'DELIVERED', 'RETRYING', 'FAILED', 'EXHAUSTED', 'PENDING'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                statusFilter === s
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-surface-200'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Total: {deliveries.length}</span>
        </div>
      </div>

      {/* Deliveries Table */}
      {error ? (
        <ErrorCard error={error} onRetry={fetchDeliveries} />
      ) : isLoading ? (
        <Card className="p-6 space-y-4">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </Card>
      ) : deliveries.length === 0 ? (
        <EmptyState
          icon={BellRing}
          title="No Delivery Records Found"
          description="Outbound notification events emitted by alerts, incidents, or reports will be recorded here with delivery receipts."
        />
      ) : (
        <Table data={deliveries} columns={columns} keyExtractor={(d) => d.id} />
      )}

      {/* Delivery Inspection Modal */}
      {selectedDelivery && (
        <Modal
          isOpen={Boolean(selectedDelivery)}
          onClose={() => setSelectedDelivery(null)}
          title="Notification Delivery Audit Record"
          maxWidth="xl"
        >
          <div className="space-y-4 text-xs font-mono">
            <div className="grid grid-cols-2 gap-3 p-3 bg-surface-300 rounded border border-slate-700/80">
              <div>
                <span className="text-slate-400">Delivery ID:</span>
                <div className="text-slate-200 select-all font-mono">{selectedDelivery.id}</div>
              </div>
              <div>
                <span className="text-slate-400">Idempotency Key:</span>
                <div className="text-slate-200 select-all truncate">{selectedDelivery.idempotency_key}</div>
              </div>
              <div>
                <span className="text-slate-400">Status:</span>
                <div className="mt-0.5">{getStatusBadge(selectedDelivery.status)}</div>
              </div>
              <div>
                <span className="text-slate-400">Attempts / Max:</span>
                <div className="text-slate-200">
                  {selectedDelivery.attempt_count} / {selectedDelivery.max_attempts}
                </div>
              </div>
              <div>
                <span className="text-slate-400">Created:</span>
                <div className="text-slate-200">{formatDate(selectedDelivery.created_at)}</div>
              </div>
              <div>
                <span className="text-slate-400">Delivered / Last Attempt:</span>
                <div className="text-slate-200">
                  {selectedDelivery.delivered_at
                    ? formatDate(selectedDelivery.delivered_at)
                    : selectedDelivery.last_attempted_at
                    ? formatDate(selectedDelivery.last_attempted_at)
                    : '—'}
                </div>
              </div>
            </div>

            {selectedDelivery.failure_reason && (
              <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 rounded">
                <span className="font-bold text-red-200 block mb-1">Failure Reason:</span>
                {selectedDelivery.failure_reason}
              </div>
            )}

            {/* Event Payload Inspection */}
            {selectedDelivery.event && (
              <div className="space-y-1">
                <span className="text-slate-400 block">Event Payload (Sanitized):</span>
                <pre className="p-3 bg-surface-400/80 rounded border border-slate-800 text-slate-300 overflow-x-auto max-h-48 text-[11px]">
                  {JSON.stringify(selectedDelivery.event.payload, null, 2)}
                </pre>
              </div>
            )}

            {/* Response Metadata */}
            {selectedDelivery.response_metadata && Object.keys(selectedDelivery.response_metadata).length > 0 && (
              <div className="space-y-1">
                <span className="text-slate-400 block">Destination Response Metadata:</span>
                <pre className="p-3 bg-surface-400/80 rounded border border-slate-800 text-slate-300 overflow-x-auto max-h-36 text-[11px]">
                  {JSON.stringify(selectedDelivery.response_metadata, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex justify-between items-center pt-3 border-t border-slate-800">
              <div className="flex gap-2">
                {canRetry && (selectedDelivery.status === 'FAILED' || selectedDelivery.status === 'EXHAUSTED') && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      handleRetry(selectedDelivery.id);
                      setSelectedDelivery(null);
                    }}
                    className="text-blue-400 border-blue-800"
                  >
                    <RotateCcw className="w-3.5 h-3.5 mr-1" />
                    Retry Delivery
                  </Button>
                )}
                {canCancel && (selectedDelivery.status === 'PENDING' || selectedDelivery.status === 'RETRYING') && (
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => {
                      handleCancel(selectedDelivery.id);
                      setSelectedDelivery(null);
                    }}
                  >
                    <XCircle className="w-3.5 h-3.5 mr-1" />
                    Cancel Delivery
                  </Button>
                )}
              </div>

              <Button variant="ghost" size="sm" onClick={() => setSelectedDelivery(null)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
