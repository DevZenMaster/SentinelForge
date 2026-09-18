'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  AlertOctagon,
  ArrowLeft,
  Clock,
  ShieldAlert,
  UserCheck,
  CheckCircle,
  RefreshCw,
  MessageSquare,
  History,
  Send,
} from 'lucide-react';
import { Incident, IncidentStatus, IncidentSeverity } from '@/types/incident';
import { apiClient } from '@/lib/api/client';
import { useAuth } from '@/lib/auth/context';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { Skeleton } from '@/components/ui/Skeleton';
import { formatDate, formatTimeAgo } from '@/lib/utils';

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const incidentId = params.id as string;
  const { hasPermission } = useAuth();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchIncident = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiClient.get<Incident>(`/api/v1/incidents/${incidentId}`);
      setIncident(data);

      try {
        const tData = await apiClient.get<{ items: any[] }>(
          `/api/v1/incidents/${incidentId}/timeline`
        );
        setTimeline(tData.items || []);
      } catch {
        // Timeline might be optional
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load incident case.'));
    } finally {
      setIsLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    fetchIncident();
  }, [fetchIncident]);

  const handleStatusTransition = async (targetStatus: IncidentStatus) => {
    if (!incident) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const updated = await apiClient.post<Incident>(
        `/api/v1/incidents/${incident.id}/transition`,
        { target_status: targetStatus }
      );
      setIncident(updated);
      fetchIncident();
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to update incident status.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading && !incident) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="text-center py-12">
        <p className="text-sm font-mono text-slate-400">Incident case not found.</p>
        <Link href="/incidents">
          <Button size="sm" variant="outline" className="mt-4">
            Return to Incidents
          </Button>
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Breadcrumb & Action Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-3">
          <Link href="/incidents">
            <Button size="sm" variant="ghost" className="gap-1 text-slate-400 hover:text-slate-200">
              <ArrowLeft className="w-3.5 h-3.5" />
              Incidents
            </Button>
          </Link>
          <div className="h-4 w-px bg-slate-800" />
          <span className="text-xs font-mono text-slate-400 truncate max-w-md">
            Case: {incident.id}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Status Transitions */}
          {hasPermission('incidents.update') && (
            <div className="flex items-center gap-1.5 bg-surface-200 p-1 rounded border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 px-2">Transition:</span>
              {(['IN_PROGRESS', 'CONTAINED', 'RESOLVED', 'CLOSED'] as IncidentStatus[]).map(
                (st) =>
                  st !== incident.status && (
                    <Button
                      key={st}
                      size="sm"
                      variant="ghost"
                      disabled={isSubmitting}
                      onClick={() => handleStatusTransition(st)}
                      className="text-[11px] font-mono py-0.5 px-2 hover:bg-surface-100 text-slate-300"
                    >
                      {st.replace('_', ' ')}
                    </Button>
                  )
              )}
            </div>
          )}

          <Button
            size="sm"
            variant="ghost"
            onClick={fetchIncident}
            isLoading={isLoading}
            className="text-xs font-mono p-1.5"
            title="Reload Record"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      <ErrorCard error={error} onRetry={fetchIncident} />

      {/* Case Header Card */}
      <div className="p-5 rounded-lg bg-surface-200 border border-slate-800 space-y-4">
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <Badge variant="severity" severity={incident.severity} />
              <Badge variant="status" status={incident.status} dot />
            </div>
            <h1 className="text-lg font-bold font-mono text-slate-100">{incident.title}</h1>
            <p className="text-xs text-slate-300 font-mono mt-1 whitespace-pre-wrap">
              {incident.description}
            </p>
          </div>

          <div className="flex items-center gap-4 bg-surface-300/80 p-3 rounded border border-slate-800 self-start text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px]">Lead Analyst</span>
              <span className="text-slate-200 font-semibold">
                {incident.lead_analyst ? incident.lead_analyst.username : 'Unassigned'}
              </span>
            </div>
            <div className="h-6 w-px bg-slate-700/60" />
            <div>
              <span className="text-slate-500 block text-[10px]">Opened</span>
              <span className="text-slate-300">{formatTimeAgo(incident.created_at)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Linked Alerts & Investigation Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Linked Alerts */}
        <Card
          header={
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
              Linked Security Alerts ({incident.alerts?.length || 0})
            </span>
          }
        >
          {!incident.alerts?.length ? (
            <p className="text-xs font-mono text-slate-500 text-center py-6">
              No detection alerts linked to this incident case yet.
            </p>
          ) : (
            <div className="space-y-2 font-mono text-xs max-h-96 overflow-y-auto">
              {incident.alerts.map((a) => (
                <Link
                  key={a.id}
                  href={`/alerts/${a.id}`}
                  className="block p-3 rounded bg-surface-300/60 border border-slate-800 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-slate-100 hover:text-blue-400">
                      {a.title}
                    </span>
                    <Badge variant="severity" severity={a.severity} />
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>Priority Score: {a.priority_score}</span>
                    <span>{formatTimeAgo(a.created_at)}</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Card>

        {/* Timeline Stream */}
        <Card
          header={
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
              Case Investigation Timeline ({timeline.length})
            </span>
          }
        >
          {!timeline.length ? (
            <p className="text-xs font-mono text-slate-500 text-center py-6">
              No timeline events recorded yet.
            </p>
          ) : (
            <div className="space-y-3 font-mono text-xs max-h-96 overflow-y-auto">
              {timeline.map((entry, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded bg-surface-300/40 border border-slate-800 flex flex-col gap-1"
                >
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span className="text-blue-400 font-semibold">{entry.event_type || 'UPDATE'}</span>
                    <span>{formatTimeAgo(entry.timestamp)}</span>
                  </div>
                  <div className="text-slate-200 text-xs">{entry.description || entry.summary}</div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
