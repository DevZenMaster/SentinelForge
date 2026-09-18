'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldAlert,
  Clock,
  UserCheck,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ArrowLeft,
  RefreshCw,
  Search,
  MessageSquare,
  History,
  Link2,
  Send,
  Plus,
} from 'lucide-react';
import {
  AlertDetail,
  AlertNote,
  AlertStatus,
} from '@/types/alert';
import { UserListItem } from '@/types/auth';
import { PaginatedList } from '@/types/api';
import { apiClient, ConcurrencyConflictError } from '@/lib/api/client';
import { useAuth } from '@/lib/auth/context';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Modal } from '@/components/ui/Modal';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { Skeleton } from '@/components/ui/Skeleton';
import { formatDate, formatTimeAgo } from '@/lib/utils';

export default function AlertDetailPage() {
  const params = useParams();
  const router = useRouter();
  const alertId = params.id as string;
  const { hasPermission } = useAuth();

  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [notes, setNotes] = useState<AlertNote[]>([]);
  const [users, setUsers] = useState<UserListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Modals state
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [selectedAssigneeId, setSelectedAssigneeId] = useState('');
  const [showSuppressModal, setShowSuppressModal] = useState(false);
  const [suppressReason, setSuppressReason] = useState('');
  const [suppressDuration, setSuppressDuration] = useState(1440); // 24h default
  const [showResolveModal, setShowResolveModal] = useState(false);
  const [resolutionReason, setResolutionReason] = useState('');
  const [showCloseModal, setShowCloseModal] = useState(false);
  const [closeReason, setCloseReason] = useState('');
  const [showLinkIncidentModal, setShowLinkIncidentModal] = useState(false);
  const [incidentIdToLink, setIncidentIdToLink] = useState('');
  const [newNoteContent, setNewNoteContent] = useState('');

  const fetchAlert = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const alertData = await apiClient.get<AlertDetail>(`/api/v1/alerts/${alertId}`);
      setAlert(alertData);

      // Fetch triage notes
      try {
        const notesData = await apiClient.get<PaginatedList<AlertNote>>(
          `/api/v1/alerts/${alertId}/notes?limit=100`
        );
        setNotes(notesData.items || []);
      } catch {
        // Notes might be empty or restricted
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to load alert details.'));
    } finally {
      setIsLoading(false);
    }
  }, [alertId]);

  useEffect(() => {
    fetchAlert();
  }, [fetchAlert]);

  // Load user directory for assignment selection
  const loadUsers = async () => {
    try {
      const data = await apiClient.get<PaginatedList<UserListItem>>('/api/v1/users?is_active=true');
      setUsers(data.items || []);
    } catch {
      // Fallback
    }
  };

  // 1. Acknowledge Alert
  const handleAcknowledge = async () => {
    if (!alert) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const updated = await apiClient.post<AlertDetail>(
        `/api/v1/alerts/${alert.id}/acknowledge`,
        { version: alert.version }
      );
      setAlert(updated);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to acknowledge alert.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  // 2. Assign Alert
  const handleAssign = async () => {
    if (!alert || !selectedAssigneeId) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const updated = await apiClient.post<AlertDetail>(
        `/api/v1/alerts/${alert.id}/assign`,
        { assignee_id: selectedAssigneeId, version: alert.version }
      );
      setAlert(updated);
      setShowAssignModal(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to assign alert.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  // 3. Suppress Alert
  const handleSuppress = async () => {
    if (!alert || !suppressReason.trim()) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const updated = await apiClient.post<AlertDetail>(
        `/api/v1/alerts/${alert.id}/suppress`,
        {
          reason: suppressReason.trim(),
          duration_minutes: Number(suppressDuration),
          version: alert.version,
        }
      );
      setAlert(updated);
      setShowSuppressModal(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to suppress alert.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  // 4. Resolve Alert
  const handleResolve = async () => {
    if (!alert || !resolutionReason.trim()) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const updated = await apiClient.post<AlertDetail>(
        `/api/v1/alerts/${alert.id}/resolve`,
        {
          resolution_reason: resolutionReason.trim(),
          version: alert.version,
        }
      );
      setAlert(updated);
      setShowResolveModal(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to resolve alert.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  // 5. Close Alert
  const handleClose = async () => {
    if (!alert) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const updated = await apiClient.post<AlertDetail>(
        `/api/v1/alerts/${alert.id}/close`,
        {
          close_reason: closeReason.trim() || undefined,
          version: alert.version,
        }
      );
      setAlert(updated);
      setShowCloseModal(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to close alert.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  // 6. Link to Incident
  const handleLinkIncident = async () => {
    if (!alert || !incidentIdToLink.trim()) return;
    setIsSubmitting(true);
    setError(null);
    try {
      await apiClient.post(`/api/v1/alerts/${alert.id}/incidents`, {
        incident_id: incidentIdToLink.trim(),
      });
      setShowLinkIncidentModal(false);
      fetchAlert();
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to link alert to incident.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  // 7. Add Triage Note (Append-only)
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!alert || !newNoteContent.trim()) return;
    setIsSubmitting(true);
    try {
      const note = await apiClient.post<AlertNote>(`/api/v1/alerts/${alert.id}/notes`, {
        content: newNoteContent.trim(),
      });
      setNotes((prev) => [note, ...prev]);
      setNewNoteContent('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err : new Error('Failed to post triage note.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading && !alert) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="text-center py-12">
        <p className="text-sm font-mono text-slate-400">Security alert record not found.</p>
        <Link href="/alerts">
          <Button size="sm" variant="outline" className="mt-4">
            Return to Alerts Queue
          </Button>
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Action Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-3">
          <Link href="/alerts">
            <Button size="sm" variant="ghost" className="gap-1 text-slate-400 hover:text-slate-200">
              <ArrowLeft className="w-3.5 h-3.5" />
              Alerts
            </Button>
          </Link>
          <div className="h-4 w-px bg-slate-800" />
          <span className="text-xs font-mono text-slate-400 truncate max-w-md">
            ID: {alert.id}
          </span>
          <span className="text-xs font-mono text-slate-500">
            (v{alert.version})
          </span>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Acknowledge Button */}
          {!alert.is_acknowledged &&
            alert.status === 'OPEN' &&
            hasPermission('alerts.acknowledge') && (
              <Button
                size="sm"
                variant="primary"
                onClick={handleAcknowledge}
                isLoading={isSubmitting}
                className="text-xs font-mono gap-1.5"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Acknowledge
              </Button>
            )}

          {/* Assign Button */}
          {hasPermission('alerts.assign') && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                loadUsers();
                setShowAssignModal(true);
              }}
              className="text-xs font-mono gap-1.5"
            >
              <UserCheck className="w-3.5 h-3.5" />
              {alert.assignee ? 'Reassign' : 'Assign Analyst'}
            </Button>
          )}

          {/* Suppress Button */}
          {alert.status !== 'SUPPRESSED' &&
            alert.status !== 'CLOSED' &&
            hasPermission('alerts.suppress') && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowSuppressModal(true)}
                className="text-xs font-mono gap-1.5"
              >
                Suppress
              </Button>
            )}

          {/* Resolve Button */}
          {alert.status !== 'RESOLVED' &&
            alert.status !== 'CLOSED' &&
            hasPermission('alerts.resolve') && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowResolveModal(true)}
                className="text-xs font-mono gap-1.5"
              >
                Resolve
              </Button>
            )}

          {/* Close Button */}
          {alert.status !== 'CLOSED' && hasPermission('alerts.close') && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowCloseModal(true)}
              className="text-xs font-mono gap-1.5"
            >
              Close
            </Button>
          )}

          {/* Link Incident Button */}
          {hasPermission('incidents.update') && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowLinkIncidentModal(true)}
              className="text-xs font-mono gap-1.5"
            >
              <Link2 className="w-3.5 h-3.5" />
              Link Incident
            </Button>
          )}

          {/* Pivot Investigation */}
          {(alert.source_ip || alert.username) && (
            <Link
              href={
                alert.source_ip
                  ? `/investigations?ip=${encodeURIComponent(alert.source_ip)}`
                  : `/investigations?user=${encodeURIComponent(alert.username || '')}`
              }
            >
              <Button size="sm" variant="ghost" className="text-xs font-mono gap-1.5 text-cyan-400">
                <Search className="w-3.5 h-3.5" />
                Investigate Pivot
              </Button>
            </Link>
          )}

          <Button
            size="sm"
            variant="ghost"
            onClick={fetchAlert}
            isLoading={isLoading}
            className="text-xs font-mono p-1.5"
            title="Reload Record"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* 409 Concurrency Conflict & Error Callout */}
      <ErrorCard error={error} onRetry={fetchAlert} />

      {/* Header Card: Title, Severity, Status, Priority */}
      <div className="p-5 rounded-lg bg-surface-200 border border-slate-800 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 flex-wrap mb-1.5">
              <Badge variant="severity" severity={alert.severity} />
              <Badge variant="status" status={alert.status} dot />
              {alert.sla_breached && (
                <span className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800 text-xs font-mono uppercase font-semibold">
                  SLA Breached (&gt;24h)
                </span>
              )}
            </div>
            <h1 className="text-lg font-bold font-mono text-slate-100">{alert.title}</h1>
            {alert.description && (
              <p className="text-xs text-slate-400 font-mono mt-1">{alert.description}</p>
            )}
          </div>

          <div className="flex items-center gap-4 bg-surface-300/80 p-3 rounded border border-slate-800 self-start">
            <div className="text-center">
              <div className="text-[10px] uppercase font-mono text-slate-400">Priority Score</div>
              <div
                className={`text-xl font-bold font-mono ${
                  alert.priority_score >= 80
                    ? 'text-red-400'
                    : alert.priority_score >= 60
                    ? 'text-orange-400'
                    : 'text-slate-200'
                }`}
              >
                {alert.priority_score} / 100
              </div>
            </div>
            <div className="h-8 w-px bg-slate-700/60" />
            <div className="text-center">
              <div className="text-[10px] uppercase font-mono text-slate-400">Telemetry Events</div>
              <div className="text-xl font-bold font-mono text-slate-200">
                {alert.event_count}
              </div>
            </div>
          </div>
        </div>

        {/* Metadata Details Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
          <div>
            <span className="text-slate-500 block text-[11px]">Detection Rule</span>
            <span className="text-slate-200 font-semibold">{alert.rule_name}</span>
            <span className="text-slate-500 text-[10px] ml-1">(v{alert.rule_version})</span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px]">Source IP</span>
            <span className="text-slate-200 font-semibold">
              {alert.source_ip ? (
                <Link
                  href={`/investigations?ip=${encodeURIComponent(alert.source_ip)}`}
                  className="hover:underline text-blue-400"
                >
                  {alert.source_ip}
                </Link>
              ) : (
                '—'
              )}
            </span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px]">Username</span>
            <span className="text-slate-200 font-semibold">
              {alert.username ? (
                <Link
                  href={`/investigations?user=${encodeURIComponent(alert.username)}`}
                  className="hover:underline text-blue-400"
                >
                  {alert.username}
                </Link>
              ) : (
                '—'
              )}
            </span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px]">Assigned Analyst</span>
            <span className="text-slate-200 font-semibold">
              {alert.assignee ? alert.assignee.username : <span className="text-slate-500 italic">Unassigned</span>}
            </span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px]">First Seen</span>
            <span className="text-slate-300">{formatDate(alert.first_seen)}</span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px]">Last Seen</span>
            <span className="text-slate-300">{formatDate(alert.last_seen)}</span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px]">Created At</span>
            <span className="text-slate-300">{formatDate(alert.created_at)}</span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px]">Acknowledged By</span>
            <span className="text-slate-300">
              {alert.acknowledged_by ? alert.acknowledged_by.username : '—'}
            </span>
          </div>
        </div>

        {/* Suppression / Resolution notes if present */}
        {alert.status === 'SUPPRESSED' && alert.suppression_reason && (
          <div className="p-3 bg-surface-300/80 border border-slate-700 rounded text-xs font-mono text-slate-300">
            <span className="font-semibold text-slate-200">Suppression Note:</span>{' '}
            {alert.suppression_reason} (Expires:{' '}
            {formatDate(alert.suppression_expires_at)})
          </div>
        )}

        {alert.status === 'RESOLVED' && alert.resolution_reason && (
          <div className="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded text-xs font-mono text-emerald-300">
            <span className="font-semibold">Resolution Summary:</span> {alert.resolution_reason}
          </div>
        )}
      </div>

      {/* Tabs / Two Column Layout: Events & Analyst Notes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Triggering Events */}
        <Card
          header={
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
              Triggering Events ({alert.events?.length || 0})
            </span>
          }
        >
          {!alert.events?.length ? (
            <p className="text-xs font-mono text-slate-500 text-center py-6">
              No triggering events linked to this alert record.
            </p>
          ) : (
            <div className="space-y-2 font-mono text-xs max-h-96 overflow-y-auto">
              {alert.events.map((ev) => (
                <div
                  key={ev.id}
                  className="p-2.5 rounded bg-surface-300/60 border border-slate-800 flex items-center justify-between"
                >
                  <div className="flex flex-col">
                    <span className="font-semibold text-slate-200">
                      Role: {ev.role}
                    </span>
                    <span className="text-[11px] text-slate-400">
                      Event ID: {ev.event_id}
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-500">
                    {formatDate(ev.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Analyst Triage Notes (Strict XSS Safe) */}
        <Card
          header={
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
              Analyst Triage Notes ({notes.length})
            </span>
          }
        >
          <div className="space-y-4">
            {/* Note Creation Form */}
            {hasPermission('alerts.notes.create') && (
              <form onSubmit={handleAddNote} className="space-y-2">
                <textarea
                  rows={2}
                  value={newNoteContent}
                  onChange={(e) => setNewNoteContent(e.target.value)}
                  placeholder="Add triage investigation findings (HTML/XSS escaped)..."
                  className="w-full p-2.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500 transition-colors"
                />
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    size="sm"
                    variant="primary"
                    disabled={!newNoteContent.trim() || isSubmitting}
                    isLoading={isSubmitting}
                    className="text-xs font-mono gap-1"
                  >
                    <Send className="w-3 h-3" />
                    Append Note
                  </Button>
                </div>
              </form>
            )}

            {/* Notes List (Strictly text escaped) */}
            {!notes.length ? (
              <p className="text-xs font-mono text-slate-500 text-center py-6">
                No analyst triage notes recorded yet.
              </p>
            ) : (
              <div className="space-y-2.5 max-h-96 overflow-y-auto">
                {notes.map((note) => (
                  <div
                    key={note.id}
                    className="p-3 rounded bg-surface-300/40 border border-slate-800 space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span className="font-semibold text-blue-400">
                        @{note.author_username}
                      </span>
                      <span>{formatTimeAgo(note.created_at)}</span>
                    </div>
                    {/* Plain text rendering safe against XSS */}
                    <div className="text-xs text-slate-200 font-mono whitespace-pre-wrap break-words">
                      {note.content}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Assignment Modal */}
      <Modal
        isOpen={showAssignModal}
        onClose={() => setShowAssignModal(false)}
        title="Assign Alert to Analyst"
        description="Select an active security analyst from the operational directory."
      >
        <div className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Select Analyst</label>
            <select
              value={selectedAssigneeId}
              onChange={(e) => setSelectedAssigneeId(e.target.value)}
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="">-- Select Active Analyst --</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.username} ({u.roles.join(', ')})
                </option>
              ))}
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <Button variant="ghost" onClick={() => setShowAssignModal(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleAssign}
              disabled={!selectedAssigneeId || isSubmitting}
              isLoading={isSubmitting}
            >
              Confirm Assignment
            </Button>
          </div>
        </div>
      </Modal>

      {/* Suppress Modal */}
      <Modal
        isOpen={showSuppressModal}
        onClose={() => setShowSuppressModal(false)}
        title="Suppress Alert"
        description="Temporarily suppress alert notifications with documented operational reason."
      >
        <div className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Suppression Duration</label>
            <select
              value={suppressDuration}
              onChange={(e) => setSuppressDuration(Number(e.target.value))}
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value={60}>1 Hour</option>
              <option value={360}>6 Hours</option>
              <option value={1440}>24 Hours (1 Day)</option>
              <option value={10080}>7 Days (1 Week)</option>
              <option value={43200}>30 Days (Max)</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Mandatory Suppression Reason</label>
            <textarea
              rows={3}
              value={suppressReason}
              onChange={(e) => setSuppressReason(e.target.value)}
              placeholder="Document reason for suppression (e.g. Authorized red team activity)..."
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <Button variant="ghost" onClick={() => setShowSuppressModal(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleSuppress}
              disabled={!suppressReason.trim() || isSubmitting}
              isLoading={isSubmitting}
            >
              Suppress Alert
            </Button>
          </div>
        </div>
      </Modal>

      {/* Resolve Modal */}
      <Modal
        isOpen={showResolveModal}
        onClose={() => setShowResolveModal(false)}
        title="Resolve Alert"
        description="Conclude alert investigation with verified resolution documentation."
      >
        <div className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Resolution Findings / Reason</label>
            <textarea
              rows={3}
              value={resolutionReason}
              onChange={(e) => setResolutionReason(e.target.value)}
              placeholder="Document resolution (e.g. Verified benign scanner activity from internal IT)..."
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <Button variant="ghost" onClick={() => setShowResolveModal(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleResolve}
              disabled={!resolutionReason.trim() || isSubmitting}
              isLoading={isSubmitting}
            >
              Resolve Alert
            </Button>
          </div>
        </div>
      </Modal>

      {/* Close Modal */}
      <Modal
        isOpen={showCloseModal}
        onClose={() => setShowCloseModal(false)}
        title="Close Alert"
        description="Permanently archive and close alert record."
      >
        <div className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Close Reason (Optional)</label>
            <textarea
              rows={2}
              value={closeReason}
              onChange={(e) => setCloseReason(e.target.value)}
              placeholder="Optional closure notes..."
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <Button variant="ghost" onClick={() => setShowCloseModal(false)}>
              Cancel
            </Button>
            <Button
              variant="secondary"
              onClick={handleClose}
              isLoading={isSubmitting}
            >
              Close Alert
            </Button>
          </div>
        </div>
      </Modal>

      {/* Link Incident Modal */}
      <Modal
        isOpen={showLinkIncidentModal}
        onClose={() => setShowLinkIncidentModal(false)}
        title="Link Alert to Incident Case"
        description="Attach this alert evidence to an existing active security incident case."
      >
        <div className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Incident Case UUID</label>
            <input
              type="text"
              value={incidentIdToLink}
              onChange={(e) => setIncidentIdToLink(e.target.value)}
              placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
              className="w-full p-2 bg-surface-300 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <Button variant="ghost" onClick={() => setShowLinkIncidentModal(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleLinkIncident}
              disabled={!incidentIdToLink.trim() || isSubmitting}
              isLoading={isSubmitting}
            >
              Link Incident
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
