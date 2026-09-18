'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  SlidersHorizontal,
  Plus,
  RefreshCw,
  Edit2,
  Power,
  Clock,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Send,
  Trash2,
} from 'lucide-react';
import { useAuth } from '@/lib/auth/context';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { EmptyState } from '@/components/ui/EmptyState';
import { Modal } from '@/components/ui/Modal';
import {
  NotificationPolicy,
  NotificationPolicyCreate,
  NotificationPolicyUpdate,
  Integration,
  NotificationEventType,
} from '@/types/notifications';
import { notificationsApi } from '@/lib/api/notifications';
import { formatDate, getSeverityClasses } from '@/lib/utils';

const ALL_EVENT_TYPES: { type: NotificationEventType; label: string; category: string }[] = [
  { type: 'ALERT_CREATED', label: 'Alert Created', category: 'Alerts' },
  { type: 'ALERT_ESCALATED', label: 'Alert Escalated', category: 'Alerts' },
  { type: 'ALERT_ACKNOWLEDGED', label: 'Alert Acknowledged', category: 'Alerts' },
  { type: 'ALERT_ASSIGNED', label: 'Alert Assigned', category: 'Alerts' },
  { type: 'ALERT_RESOLVED', label: 'Alert Resolved', category: 'Alerts' },
  { type: 'ALERT_CLOSED', label: 'Alert Closed', category: 'Alerts' },
  { type: 'ALERT_SUPPRESSED', label: 'Alert Suppressed', category: 'Alerts' },
  { type: 'INCIDENT_CREATED', label: 'Incident Created', category: 'Incidents' },
  { type: 'INCIDENT_STATE_CHANGED', label: 'Incident State Changed', category: 'Incidents' },
  { type: 'INCIDENT_RESOLVED', label: 'Incident Resolved', category: 'Incidents' },
  { type: 'SLA_BREACH_DETECTED', label: 'SLA Breach Detected', category: 'SLA' },
  { type: 'REPORT_EXPORTED', label: 'Report Exported', category: 'Compliance' },
];

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export default function NotificationPoliciesPage() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission('notification_policies.read');
  const canCreate = hasPermission('notification_policies.create');
  const canUpdate = hasPermission('notification_policies.update');
  const canEnable = hasPermission('notification_policies.enable');
  const canDisable = hasPermission('notification_policies.disable');

  const [policies, setPolicies] = useState<NotificationPolicy[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<Error | null>(null);

  // Modal states
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [isEditOpen, setIsEditOpen] = useState<boolean>(false);
  const [editingPolicy, setEditingPolicy] = useState<NotificationPolicy | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  // Policy Form state
  const [formName, setFormName] = useState<string>('');
  const [formDescription, setFormDescription] = useState<string>('');
  const [formEventTypes, setFormEventTypes] = useState<string[]>(['ALERT_CREATED']);
  const [formMinSeverity, setFormMinSeverity] = useState<string>('');
  const [formDestinationIds, setFormDestinationIds] = useState<string[]>([]);
  const [formCooldown, setFormCooldown] = useState<number>(0);
  const [filterRuleId, setFilterRuleId] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');

  const loadData = useCallback(async () => {
    if (!canRead) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const [policiesRes, integrationsRes]: any = await Promise.all([
        notificationsApi.listPolicies(),
        notificationsApi.listIntegrations(),
      ]);
      setPolicies(Array.isArray(policiesRes) ? policiesRes : (policiesRes?.data || []));
      setIntegrations(Array.isArray(integrationsRes) ? integrationsRes : (integrationsRes?.data || []));
    } catch (err: any) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [canRead]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const openCreateModal = () => {
    setFormName('');
    setFormDescription('');
    setFormEventTypes(['ALERT_CREATED']);
    setFormMinSeverity('');
    setFormDestinationIds(integrations.length > 0 ? [integrations[0].id] : []);
    setFormCooldown(0);
    setFilterRuleId('');
    setFilterStatus('');
    setFormError(null);
    setIsCreateOpen(true);
  };

  const openEditModal = (policy: NotificationPolicy) => {
    setEditingPolicy(policy);
    setFormName(policy.name);
    setFormDescription(policy.description || '');
    setFormEventTypes(policy.event_types || []);
    setFormMinSeverity(policy.min_severity || '');
    setFormDestinationIds(policy.destination_ids || []);
    setFormCooldown(policy.cooldown_seconds || 0);
    setFilterRuleId(policy.filters?.rule_id || '');
    setFilterStatus(policy.filters?.status || '');
    setFormError(null);
    setIsEditOpen(true);
  };

  const handleToggleEvent = (eventType: string) => {
    if (formEventTypes.includes(eventType)) {
      if (formEventTypes.length === 1) return; // keep at least 1
      setFormEventTypes(formEventTypes.filter((t) => t !== eventType));
    } else {
      setFormEventTypes([...formEventTypes, eventType]);
    }
  };

  const handleToggleDestination = (destId: string) => {
    if (formDestinationIds.includes(destId)) {
      if (formDestinationIds.length === 1) return; // keep at least 1
      setFormDestinationIds(formDestinationIds.filter((id) => id !== destId));
    } else {
      setFormDestinationIds([...formDestinationIds, destId]);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setIsSubmitting(true);

    try {
      if (formDestinationIds.length === 0) {
        throw new Error('Please select at least one notification destination.');
      }
      if (formEventTypes.length === 0) {
        throw new Error('Please select at least one security event trigger.');
      }

      const filters: Record<string, any> = {};
      if (filterRuleId.trim()) filters.rule_id = filterRuleId.trim();
      if (filterStatus.trim()) filters.status = filterStatus.trim();

      const payload: NotificationPolicyCreate = {
        name: formName.trim(),
        description: formDescription.trim() || undefined,
        enabled: true,
        event_types: formEventTypes,
        min_severity: formMinSeverity || undefined,
        destination_ids: formDestinationIds,
        filters,
        cooldown_seconds: formCooldown,
      };

      await notificationsApi.createPolicy(payload);
      setIsCreateOpen(false);
      await loadData();
    } catch (err: any) {
      setFormError(err.message || 'Failed to create notification policy.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingPolicy) return;
    setFormError(null);
    setIsSubmitting(true);

    try {
      if (formDestinationIds.length === 0) {
        throw new Error('Please select at least one notification destination.');
      }
      if (formEventTypes.length === 0) {
        throw new Error('Please select at least one security event trigger.');
      }

      const filters: Record<string, any> = {};
      if (filterRuleId.trim()) filters.rule_id = filterRuleId.trim();
      if (filterStatus.trim()) filters.status = filterStatus.trim();

      const payload: NotificationPolicyUpdate = {
        name: formName.trim(),
        description: formDescription.trim() || undefined,
        event_types: formEventTypes,
        min_severity: formMinSeverity || undefined,
        destination_ids: formDestinationIds,
        filters,
        cooldown_seconds: formCooldown,
        version: editingPolicy.version,
      };

      await notificationsApi.updatePolicy(editingPolicy.id, payload);
      setIsEditOpen(false);
      setEditingPolicy(null);
      await loadData();
    } catch (err: any) {
      setFormError(err.message || 'Failed to update notification policy.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleEnable = async (policy: NotificationPolicy) => {
    try {
      if (policy.enabled) {
        if (!canDisable) return;
        await notificationsApi.disablePolicy(policy.id);
      } else {
        if (!canEnable) return;
        await notificationsApi.enablePolicy(policy.id);
      }
      await loadData();
    } catch (err: any) {
      alert(`Toggle failed: ${err.message || err}`);
    }
  };

  const getDestinationName = (destId: string) => {
    const d = integrations.find((i) => i.id === destId);
    return d ? `${d.name} (${d.type})` : `Destination ${destId.slice(0, 8)}`;
  };

  if (!canRead) {
    return (
      <div className="p-8">
        <ErrorCard
          error="Access Denied: You do not possess the 'notification_policies.read' permission required to inspect notification routing policies."
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
              Notification Policies & Routing
            </h1>
            <Badge variant="outline" className="font-mono text-xs text-blue-400 border-blue-500/30">
              Phase 13
            </Badge>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Declarative rule-based dispatch filters, severity thresholds, destination binding, and cooldown controls.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={loadData}
            disabled={isLoading}
            className="flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>

          {canCreate && (
            <Button
              variant="primary"
              size="sm"
              onClick={openCreateModal}
              disabled={integrations.length === 0}
              className="flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              New Policy
            </Button>
          )}
        </div>
      </div>

      {integrations.length === 0 && !isLoading && (
        <div className="p-4 rounded-lg bg-amber-950/40 border border-amber-800 text-amber-300 text-sm flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>
            No destinations configured. Please register at least one integration destination in the{' '}
            <a href="/integrations" className="underline font-semibold hover:text-amber-200">
              Integrations Workspace
            </a>{' '}
            before defining policies.
          </span>
        </div>
      )}

      {/* Policies List */}
      {error ? (
        <ErrorCard error={error} onRetry={loadData} />
      ) : isLoading ? (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <Card key={i} className="p-5 space-y-3">
              <Skeleton className="h-6 w-1/3" />
              <Skeleton className="h-4 w-2/3" />
            </Card>
          ))}
        </div>
      ) : policies.length === 0 ? (
        <EmptyState
          icon={SlidersHorizontal}
          title="No Notification Policies Defined"
          description="Create declarative policies to bind detection alerts, incident escalations, and SLA breaches to external destinations."
          action={
            canCreate && integrations.length > 0 ? (
              <Button variant="primary" size="sm" onClick={openCreateModal}>
                <Plus className="w-4 h-4 mr-2" />
                Define First Policy
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-4">
          {policies.map((p) => (
            <Card
              key={p.id}
              className={`p-5 border transition-all ${
                p.enabled ? 'border-slate-800 bg-surface-200' : 'border-slate-800/60 bg-surface-400/30 opacity-75'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
                <div className="space-y-3 flex-1">
                  <div className="flex items-center gap-3">
                    <h3 className="font-semibold text-slate-100 text-base">{p.name}</h3>
                    <Badge variant={p.enabled ? 'success' : 'neutral'} className="text-[10px] font-mono uppercase">
                      {p.enabled ? 'Active' : 'Disabled'}
                    </Badge>
                    {p.min_severity && (
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          getSeverityClasses(p.min_severity).badge
                        }`}
                      >
                        ≥ {p.min_severity}
                      </span>
                    )}
                  </div>

                  {p.description && <p className="text-xs text-slate-400">{p.description}</p>}

                  {/* Trigger events badges */}
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[11px] font-mono text-slate-500 mr-1">Events:</span>
                    {p.event_types.map((et) => (
                      <span
                        key={et}
                        className="px-2 py-0.5 rounded bg-blue-950/60 border border-blue-800/80 text-blue-300 font-mono text-[10px]"
                      >
                        {et}
                      </span>
                    ))}
                  </div>

                  {/* Bound Destinations */}
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[11px] font-mono text-slate-500 mr-1">Destinations:</span>
                    {p.destination_ids.map((id) => (
                      <span
                        key={id}
                        className="px-2 py-0.5 rounded bg-surface-300 border border-slate-700 text-slate-200 font-mono text-[10px] flex items-center gap-1"
                      >
                        <Send className="w-2.5 h-2.5 text-slate-400" />
                        {getDestinationName(id)}
                      </span>
                    ))}
                  </div>

                  {/* Cooldown & Filters */}
                  <div className="flex flex-wrap gap-4 text-[11px] font-mono text-slate-400 pt-1">
                    {p.cooldown_seconds > 0 && (
                      <div className="flex items-center gap-1 text-amber-400/90">
                        <Clock className="w-3 h-3" />
                        <span>Cooldown: {p.cooldown_seconds}s</span>
                      </div>
                    )}

                    {p.filters && Object.keys(p.filters).length > 0 && (
                      <div className="flex items-center gap-1 text-slate-300">
                        <Filter className="w-3 h-3 text-slate-400" />
                        <span>Filters: {JSON.stringify(p.filters)}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 lg:self-center">
                  {(canEnable || canDisable) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleToggleEnable(p)}
                      className={`p-2 ${p.enabled ? 'text-emerald-400 hover:text-emerald-300' : 'text-slate-400'}`}
                      title={p.enabled ? 'Disable policy' : 'Enable policy'}
                    >
                      <Power className="w-4 h-4" />
                    </Button>
                  )}

                  {canUpdate && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openEditModal(p)}
                      className="flex items-center gap-1 text-xs"
                    >
                      <Edit2 className="w-3.5 h-3.5" />
                      Edit
                    </Button>
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Create / Edit Policy Modal */}
      {(isCreateOpen || isEditOpen) && (
        <Modal
          isOpen={isCreateOpen || isEditOpen}
          onClose={() => {
            setIsCreateOpen(false);
            setIsEditOpen(false);
            setEditingPolicy(null);
          }}
          title={isCreateOpen ? 'Create Notification Policy' : `Edit Policy: ${editingPolicy?.name}`}
          maxWidth="xl"
        >
          <form onSubmit={isCreateOpen ? handleCreate : handleEdit} className="space-y-4">
            {formError && (
              <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                <span>{formError}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Policy Name *</label>
              <input
                type="text"
                required
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="e.g. Critical Incident Pager"
                className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Description</label>
              <textarea
                rows={2}
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                placeholder="Optional description of routing purpose"
                className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Event Types Multi-Select */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5">
                Trigger Security Events (Select at least 1) *
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 p-3 bg-surface-300 rounded border border-slate-700/80 max-h-48 overflow-y-auto">
                {ALL_EVENT_TYPES.map((item) => {
                  const isChecked = formEventTypes.includes(item.type);
                  return (
                    <label
                      key={item.type}
                      className={`flex items-center gap-2 p-2 rounded cursor-pointer text-xs font-mono transition-colors ${
                        isChecked ? 'bg-blue-950/80 border border-blue-800 text-blue-300' : 'text-slate-400 hover:bg-surface-200'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => handleToggleEvent(item.type)}
                        className="rounded bg-surface-400 border-slate-700 text-blue-600 focus:ring-0"
                      />
                      <span className="truncate">{item.label}</span>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Destination Selection */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5">
                Bound Destinations (Select at least 1) *
              </label>
              <div className="space-y-1.5 p-3 bg-surface-300 rounded border border-slate-700/80 max-h-36 overflow-y-auto">
                {integrations.map((dest) => {
                  const isChecked = formDestinationIds.includes(dest.id);
                  return (
                    <label
                      key={dest.id}
                      className={`flex items-center justify-between p-2 rounded cursor-pointer text-xs font-mono transition-colors ${
                        isChecked ? 'bg-indigo-950/80 border border-indigo-800 text-indigo-300' : 'text-slate-400 hover:bg-surface-200'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => handleToggleDestination(dest.id)}
                          className="rounded bg-surface-400 border-slate-700 text-indigo-600 focus:ring-0"
                        />
                        <span className="font-semibold text-slate-200">{dest.name}</span>
                        <span className="text-[10px] text-slate-500">[{dest.type}]</span>
                      </div>
                      <span className="text-[10px] text-slate-500 truncate max-w-[200px]">
                        {dest.endpoint_url || dest.email_recipients?.join(', ')}
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Minimum Severity Filter</label>
                <select
                  value={formMinSeverity}
                  onChange={(e) => setFormMinSeverity(e.target.value)}
                  className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
                >
                  <option value="">Any Severity (No Threshold)</option>
                  {SEVERITY_OPTIONS.map((s) => (
                    <option key={s} value={s}>
                      ≥ {s}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Cooldown Period (Seconds, 0-86400)
                </label>
                <input
                  type="number"
                  min={0}
                  max={86400}
                  value={formCooldown}
                  onChange={(e) => setFormCooldown(parseInt(e.target.value) || 0)}
                  className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>
            </div>

            {/* Declarative Filter Criteria */}
            <div className="p-3 bg-surface-300/50 rounded border border-slate-800 space-y-3">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                Declarative Filter Criteria (Optional)
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-mono text-slate-400 mb-1">Rule ID (UUID)</label>
                  <input
                    type="text"
                    value={filterRuleId}
                    onChange={(e) => setFilterRuleId(e.target.value)}
                    placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
                    className="w-full bg-surface-300 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-mono text-slate-400 mb-1">Status Field Match</label>
                  <input
                    type="text"
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    placeholder="e.g. OPEN or ESCALATED"
                    className="w-full bg-surface-300 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setIsCreateOpen(false);
                  setIsEditOpen(false);
                  setEditingPolicy(null);
                }}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" isLoading={isSubmitting}>
                {isCreateOpen ? 'Create Policy' : 'Save Policy'}
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
