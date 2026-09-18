'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Webhook,
  Mail,
  Plus,
  RefreshCw,
  Trash2,
  Edit2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Send,
  Power,
  Key,
} from 'lucide-react';
import { useAuth } from '@/lib/auth/context';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { EmptyState } from '@/components/ui/EmptyState';
import { Modal } from '@/components/ui/Modal';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Integration, IntegrationCreate, IntegrationUpdate, NotificationTestResponse } from '@/types/notifications';
import { notificationsApi } from '@/lib/api/notifications';
import { formatTimeAgo } from '@/lib/utils';
interface EditingIntegrationState extends Integration {
  secret_token?: string;
}

export default function IntegrationsPage() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission('integrations.read');
  const canCreate = hasPermission('integrations.create');
  const canUpdate = hasPermission('integrations.update');
  const canDelete = hasPermission('integrations.delete');
  const canEnable = hasPermission('integrations.enable');
  const canDisable = hasPermission('integrations.disable');

  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<Error | null>(null);

  // Filter state
  const [typeFilter, setTypeFilter] = useState<string>('ALL');

  // Modal states
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [isEditOpen, setIsEditOpen] = useState<boolean>(false);
  const [editingIntegration, setEditingIntegration] = useState<EditingIntegrationState | null>(null);
  const [deletingIntegration, setDeletingIntegration] = useState<Integration | null>(null);
  const [testResult, setTestResult] = useState<{ integrationName: string; res: NotificationTestResponse } | null>(null);

  // Form states
  const [createForm, setCreateForm] = useState<IntegrationCreate>({
    name: '',
    type: 'WEBHOOK',
    endpoint_url: '',
    email_recipients: [],
    secret_token: '',
    enabled: true,
  });
  const [emailInput, setEmailInput] = useState<string>('');
  const [formError, setFormError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [testingId, setTestingId] = useState<string | null>(null);

  const fetchIntegrations = useCallback(async () => {
    if (!canRead) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const params = typeFilter !== 'ALL' ? { type: typeFilter } : undefined;
      const res: any = await notificationsApi.listIntegrations(params);
      setIntegrations(Array.isArray(res) ? res : (res?.data || []));
    } catch (err: any) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [canRead, typeFilter]);

  useEffect(() => {
    fetchIntegrations();
  }, [fetchIntegrations]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setIsSubmitting(true);

    try {
      let recipients: string[] | undefined = undefined;
      if (createForm.type === 'EMAIL') {
        recipients = emailInput
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        if (recipients.length === 0) {
          throw new Error('Please enter at least one valid recipient email address.');
        }
      }

      const payload: IntegrationCreate = {
        name: createForm.name.trim(),
        type: createForm.type,
        enabled: createForm.enabled,
        endpoint_url: createForm.type === 'WEBHOOK' ? createForm.endpoint_url?.trim() : undefined,
        email_recipients: recipients,
        secret_token: createForm.secret_token?.trim() || undefined,
      };

      await notificationsApi.createIntegration(payload);
      setIsCreateOpen(false);
      setCreateForm({
        name: '',
        type: 'WEBHOOK',
        endpoint_url: '',
        email_recipients: [],
        secret_token: '',
        enabled: true,
      });
      setEmailInput('');
      await fetchIntegrations();
    } catch (err: any) {
      setFormError(err.message || 'Failed to create destination.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingIntegration) return;
    setFormError(null);
    setIsSubmitting(true);

    try {
      let recipients: string[] | undefined = undefined;
      if (editingIntegration.type === 'EMAIL') {
        recipients = emailInput
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
      }

      const updateData: IntegrationUpdate = {
        name: editingIntegration.name.trim(),
        endpoint_url: editingIntegration.type === 'WEBHOOK' ? editingIntegration.endpoint_url?.trim() : undefined,
        email_recipients: recipients,
        secret_token: editingIntegration.secret_token?.trim() || undefined,
        version: editingIntegration.version,
      };

      await notificationsApi.updateIntegration(editingIntegration.id, updateData);
      setIsEditOpen(false);
      setEditingIntegration(null);
      await fetchIntegrations();
    } catch (err: any) {
      setFormError(err.message || 'Failed to update destination.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleEnable = async (integration: Integration) => {
    try {
      if (integration.enabled) {
        if (!canDisable) return;
        await notificationsApi.disableIntegration(integration.id);
      } else {
        if (!canEnable) return;
        await notificationsApi.enableIntegration(integration.id);
      }
      await fetchIntegrations();
    } catch (err: any) {
      alert(`Operation failed: ${err.message || err}`);
    }
  };

  const handleDelete = async () => {
    if (!deletingIntegration || !canDelete) return;
    setIsSubmitting(true);
    try {
      await notificationsApi.deleteIntegration(deletingIntegration.id);
      setDeletingIntegration(null);
      await fetchIntegrations();
    } catch (err: any) {
      alert(`Deletion failed: ${err.message || err}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTest = async (integration: Integration) => {
    setTestingId(integration.id);
    try {
      const res: any = await notificationsApi.testIntegration(integration.id);
      setTestResult({
        integrationName: integration.name,
        res: res?.data || res,
      });
    } catch (err: any) {
      setTestResult({
        integrationName: integration.name,
        res: {
          destination_id: integration.id,
          destination_name: integration.name,
          destination_type: integration.type,
          status: 'FAILED',
          latency_ms: 0,
          message: err.message || 'Unknown delivery failure',
        },
      });
    } finally {
      setTestingId(null);
    }
  };

  if (!canRead) {
    return (
      <div className="p-8">
        <ErrorCard
          error="Access Denied: You do not possess the 'integrations.read' permission required to inspect external notification destinations."
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
              Notification Destinations & Integrations
            </h1>
            <Badge variant="outline" className="font-mono text-xs text-blue-400 border-blue-500/30">
              Phase 13
            </Badge>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Configure secure, SSRF-guarded outbound destinations (Webhooks, Email) with HMAC signing and write-only secrets.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchIntegrations}
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
              onClick={() => {
                setFormError(null);
                setEmailInput('');
                setIsCreateOpen(true);
              }}
              className="flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Destination
            </Button>
          )}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-3 bg-surface-300 p-3 rounded-lg border border-slate-800">
        <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Destination Type:</span>
        <div className="flex gap-2">
          {['ALL', 'WEBHOOK', 'EMAIL'].map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                typeFilter === t
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-surface-200'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      {error ? (
        <ErrorCard error={error} onRetry={fetchIntegrations} />
      ) : isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {[1, 2, 3].map((i) => (
            <Card key={i} className="p-5 space-y-4">
              <Skeleton className="h-6 w-3/4" />
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-10 w-full" />
            </Card>
          ))}
        </div>
      ) : integrations.length === 0 ? (
        <EmptyState
          icon={Webhook}
          title="No Integration Destinations Configured"
          description="Register external Webhooks or Email notification channels to receive real-time operational security alerts."
          action={
            canCreate ? (
              <Button variant="primary" size="sm" onClick={() => setIsCreateOpen(true)}>
                <Plus className="w-4 h-4 mr-2" />
                Register First Destination
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {integrations.map((item) => (
            <Card
              key={item.id}
              className={`p-5 flex flex-col justify-between border ${
                item.enabled ? 'border-slate-800 bg-surface-200' : 'border-slate-800/60 bg-surface-400/30 opacity-75'
              }`}
            >
              <div className="space-y-3">
                {/* Header */}
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {item.type === 'WEBHOOK' ? (
                      <div className="p-2 rounded bg-indigo-950/60 border border-indigo-800/80 text-indigo-400">
                        <Webhook className="w-4 h-4" />
                      </div>
                    ) : (
                      <div className="p-2 rounded bg-amber-950/60 border border-amber-800/80 text-amber-400">
                        <Mail className="w-4 h-4" />
                      </div>
                    )}
                    <div>
                      <h3 className="font-semibold text-slate-100 text-sm">{item.name}</h3>
                      <span className="text-[11px] font-mono text-slate-400">{item.type}</span>
                    </div>
                  </div>

                  <Badge
                    variant={item.enabled ? 'success' : 'neutral'}
                    className="text-[10px] font-mono uppercase"
                  >
                    {item.enabled ? 'Active' : 'Disabled'}
                  </Badge>
                </div>

                {/* Target info */}
                <div className="p-2.5 rounded bg-surface-300 border border-slate-800/80 font-mono text-xs break-all">
                  {item.type === 'WEBHOOK' ? (
                    <div className="text-slate-300 flex items-center gap-1.5">
                      <span className="text-slate-500">URL:</span>
                      <span className="truncate">{item.endpoint_url || '—'}</span>
                    </div>
                  ) : (
                    <div className="text-slate-300">
                      <span className="text-slate-500">Recipients: </span>
                      {item.email_recipients?.join(', ') || '—'}
                    </div>
                  )}
                </div>

                {/* Secret token status */}
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 pt-1">
                  <span className="flex items-center gap-1.5 text-slate-400">
                    <Key className="w-3.5 h-3.5 text-slate-400" />
                    HMAC Secret:
                  </span>
                  <span className="text-slate-300">
                    {item.secret_preview ? (
                      <code className="bg-surface-300 px-1.5 py-0.5 rounded border border-slate-700 text-amber-300">
                        {item.secret_preview}
                      </code>
                    ) : (
                      <span className="text-slate-400">Not configured</span>
                    )}
                  </span>
                </div>

                {/* Last delivery status */}
                <div className="text-[11px] font-mono text-slate-400 space-y-1 pt-1 border-t border-slate-800/60">
                  <div className="flex justify-between">
                    <span>Last Delivery:</span>
                    <span>{formatTimeAgo(item.last_delivery_at)}</span>
                  </div>
                  {item.last_successful_delivery_at && (
                    <div className="flex justify-between text-emerald-400/90">
                      <span>Last Success:</span>
                      <span>{formatTimeAgo(item.last_successful_delivery_at)}</span>
                    </div>
                  )}
                  {item.last_failed_delivery_at && (
                    <div className="flex justify-between text-red-400/90">
                      <span>Last Failure:</span>
                      <span>{formatTimeAgo(item.last_failed_delivery_at)}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleTest(item)}
                  disabled={testingId === item.id || !item.enabled}
                  className="text-xs flex items-center gap-1.5"
                >
                  <Send className={`w-3.5 h-3.5 ${testingId === item.id ? 'animate-pulse text-blue-400' : ''}`} />
                  {testingId === item.id ? 'Testing...' : 'Test'}
                </Button>

                <div className="flex items-center gap-1.5">
                  {(canEnable || canDisable) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleToggleEnable(item)}
                      title={item.enabled ? 'Disable destination' : 'Enable destination'}
                      className={`p-1.5 ${item.enabled ? 'text-emerald-400 hover:text-emerald-300' : 'text-slate-400'}`}
                    >
                      <Power className="w-4 h-4" />
                    </Button>
                  )}

                  {canUpdate && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setFormError(null);
                        setEditingIntegration(item);
                        setEmailInput(item.email_recipients?.join(', ') || '');
                        setIsEditOpen(true);
                      }}
                      className="p-1.5 text-slate-400 hover:text-slate-200"
                    >
                      <Edit2 className="w-4 h-4" />
                    </Button>
                  )}

                  {canDelete && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setDeletingIntegration(item)}
                      className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-950/30"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Create Destination Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Register Notification Destination"
        description="Add a secured Webhook endpoint or Email delivery channel."
        maxWidth="lg"
      >
        <form onSubmit={handleCreate} className="space-y-4">
          {formError && (
            <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">Destination Name *</label>
            <input
              type="text"
              required
              value={createForm.name}
              onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
              placeholder="e.g. SOC Primary Webhook"
              className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">Channel Type *</label>
            <select
              value={createForm.type}
              onChange={(e) => setCreateForm({ ...createForm, type: e.target.value as any })}
              className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
            >
              <option value="WEBHOOK">Webhook (HTTPS)</option>
              <option value="EMAIL">Email (SMTP)</option>
            </select>
          </div>

          {createForm.type === 'WEBHOOK' ? (
            <>
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Endpoint URL (HTTPS) *</label>
                <input
                  type="url"
                  required
                  value={createForm.endpoint_url || ''}
                  onChange={(e) => setCreateForm({ ...createForm, endpoint_url: e.target.value })}
                  placeholder="https://events.example.com/alerts"
                  className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Protected by SSRF guard. Loopback, private CIDRs, and cloud metadata endpoints are strictly blocked.
                </p>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  HMAC Secret Token (Write-Only)
                </label>
                <input
                  type="password"
                  value={createForm.secret_token || ''}
                  onChange={(e) => setCreateForm({ ...createForm, secret_token: e.target.value })}
                  placeholder="Leave empty to auto-generate a secure 32-byte secret"
                  className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Used for HMAC-SHA256 request payload verification (X-SentinelForge-Signature).
                </p>
              </div>
            </>
          ) : (
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">
                Recipient Email Addresses (Comma-separated) *
              </label>
              <input
                type="text"
                required
                value={emailInput}
                onChange={(e) => setEmailInput(e.target.value)}
                placeholder="soc-tier1@corp.internal, oncall@corp.internal"
                className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
          )}

          <div className="flex items-center gap-2 pt-2">
            <input
              type="checkbox"
              id="create-enabled"
              checked={createForm.enabled}
              onChange={(e) => setCreateForm({ ...createForm, enabled: e.target.checked })}
              className="rounded bg-surface-300 border-slate-700 text-blue-600 focus:ring-0"
            />
            <label htmlFor="create-enabled" className="text-xs text-slate-300 select-none">
              Enable destination immediately upon creation
            </label>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <Button type="button" variant="ghost" onClick={() => setIsCreateOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" isLoading={isSubmitting}>
              Create Destination
            </Button>
          </div>
        </form>
      </Modal>

      {/* Edit Destination Modal */}
      {editingIntegration && (
        <Modal
          isOpen={isEditOpen}
          onClose={() => {
            setIsEditOpen(false);
            setEditingIntegration(null);
          }}
          title={`Edit Destination: ${editingIntegration.name}`}
          maxWidth="lg"
        >
          <form onSubmit={handleEdit} className="space-y-4">
            {formError && (
              <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                <span>{formError}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Destination Name *</label>
              <input
                type="text"
                required
                value={editingIntegration.name}
                onChange={(e) => setEditingIntegration({ ...editingIntegration, name: e.target.value })}
                className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>

            {editingIntegration.type === 'WEBHOOK' ? (
              <>
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Endpoint URL (HTTPS) *</label>
                  <input
                    type="url"
                    required
                    value={editingIntegration.endpoint_url || ''}
                    onChange={(e) => setEditingIntegration({ ...editingIntegration, endpoint_url: e.target.value })}
                    className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    Replacement Secret Token (Optional)
                  </label>
                  <input
                    type="password"
                    value={editingIntegration.secret_token || ''}
                    onChange={(e) => setEditingIntegration({ ...editingIntegration, secret_token: e.target.value })}
                    placeholder="Leave empty to keep existing secret token"
                    className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>
              </>
            ) : (
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Recipient Email Addresses (Comma-separated) *
                </label>
                <input
                  type="text"
                  required
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                  className="w-full bg-surface-300 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>
            )}

            <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setIsEditOpen(false);
                  setEditingIntegration(null);
                }}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" isLoading={isSubmitting}>
                Save Changes
              </Button>
            </div>
          </form>
        </Modal>
      )}

      {/* Delete Confirmation */}
      {deletingIntegration && (
        <ConfirmDialog
          isOpen={Boolean(deletingIntegration)}
          onClose={() => setDeletingIntegration(null)}
          onConfirm={handleDelete}
          title="Delete Integration Destination"
          message={`Are you sure you want to permanently delete destination "${deletingIntegration.name}"? Active notification policies pointing to this destination will fail delivery.`}
          confirmText="Delete Destination"
          variant="danger"
          isLoading={isSubmitting}
        />
      )}

      {/* Test Connection Result Modal */}
      {testResult && (
        <Modal
          isOpen={Boolean(testResult)}
          onClose={() => setTestResult(null)}
          title={`Test Connection Result: ${testResult.integrationName}`}
          maxWidth="md"
        >
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              {testResult.res.status === 'SUCCESS' ? (
                <div className="p-2.5 rounded-full bg-emerald-950/60 border border-emerald-800 text-emerald-400">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
              ) : (
                <div className="p-2.5 rounded-full bg-red-950/60 border border-red-800 text-red-400">
                  <XCircle className="w-6 h-6" />
                </div>
              )}
              <div>
                <h4 className="font-semibold text-slate-100">
                  {testResult.res.status === 'SUCCESS' ? 'Delivery Successful' : 'Delivery Failed'}
                </h4>
                <p className="text-xs text-slate-400">
                  Latency: <span className="font-mono text-slate-200">{testResult.res.latency_ms} ms</span>
                  {testResult.res.http_status && (
                    <> • HTTP Status: <span className="font-mono text-slate-200">{testResult.res.http_status}</span></>
                  )}
                </p>
              </div>
            </div>

            {testResult.res.status === 'FAILED' && (
              <div className="p-3 rounded bg-red-950/40 border border-red-800/80 font-mono text-xs text-red-300 break-all">
                {testResult.res.message}
              </div>
            )}

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <Button variant="outline" size="sm" onClick={() => setTestResult(null)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
