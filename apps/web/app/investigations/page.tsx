'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import {
  Search,
  ShieldAlert,
  AlertOctagon,
  Binary,
  BookOpen,
  Clock,
  ArrowRight,
  Filter,
} from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Table, Column } from '@/components/ui/Table';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { formatDate, formatTimeAgo } from '@/lib/utils';

export default function InvestigationsPage() {
  const searchParams = useSearchParams();

  const [anchorType, setAnchorType] = useState<string>(
    searchParams.get('type') ||
      (searchParams.get('ip') ? 'SOURCE_IP' : searchParams.get('user') ? 'USERNAME' : 'SOURCE_IP')
  );
  const [anchorValue, setAnchorValue] = useState<string>(
    searchParams.get('ip') || searchParams.get('user') || searchParams.get('value') || ''
  );
  const [context, setContext] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const runInvestigation = useCallback(
    async (type: string, val: string) => {
      if (!val.trim()) return;
      setIsLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams();
        params.set('anchor_type', type);
        params.set('anchor_value', val.trim());

        const data = await apiClient.get<any>(`/api/v1/investigations/context?${params.toString()}`);
        setContext(data);
      } catch (err: unknown) {
        setError(err instanceof Error ? err : new Error('Investigation query failed.'));
        setContext(null);
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (anchorValue.trim()) {
      runInvestigation(anchorType, anchorValue);
    }
  }, [runInvestigation, anchorType, anchorValue]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    runInvestigation(anchorType, anchorValue);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100">
          Security Investigation & Correlation Analytics
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-0.5">
          Cross-entity graph pivots, temporal entity timelines and 360-degree forensic context
        </p>
      </div>

      {/* Anchor Query Form */}
      <form
        onSubmit={handleSearch}
        className="p-4 bg-surface-200 border border-slate-800 rounded-lg flex flex-wrap gap-3 items-center"
      >
        <div className="flex items-center gap-2">
          <label className="text-xs font-mono text-slate-400 uppercase tracking-wider">
            Anchor Entity:
          </label>
          <select
            value={anchorType}
            onChange={(e) => setAnchorType(e.target.value)}
            className="px-3 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="SOURCE_IP">Source IP</option>
            <option value="DESTINATION_IP">Destination IP</option>
            <option value="USERNAME">Username</option>
            <option value="ALERT">Alert UUID</option>
            <option value="INCIDENT">Incident UUID</option>
            <option value="INDICATOR">Indicator / IOC</option>
          </select>
        </div>

        <div className="relative flex-1 min-w-[260px]">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            required
            value={anchorValue}
            onChange={(e) => setAnchorValue(e.target.value)}
            placeholder="Enter entity value (e.g. 192.168.1.50 or alice)..."
            className="w-full pl-8 pr-3 py-1.5 bg-surface-300 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
          />
        </div>

        <Button
          type="submit"
          variant="primary"
          size="sm"
          isLoading={isLoading}
          disabled={!anchorValue.trim()}
          className="text-xs font-mono gap-1.5"
        >
          <Search className="w-3.5 h-3.5" />
          Execute Correlation
        </Button>
      </form>

      <ErrorCard error={error} />

      {/* Investigation Results */}
      {isLoading && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
          </div>
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      )}

      {!isLoading && context && (
        <div className="space-y-6">
          {/* Summary KPI Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-4 rounded-lg bg-surface-200 border border-slate-800">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-xs font-mono uppercase">Correlated Events</span>
                <Binary className="w-4 h-4 text-blue-400" />
              </div>
              <span className="text-2xl font-bold font-mono text-slate-100">
                {context.summary?.total_events ?? context.correlated_events?.length ?? 0}
              </span>
            </div>

            <div className="p-4 rounded-lg bg-surface-200 border border-slate-800">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-xs font-mono uppercase">Triggered Alerts</span>
                <ShieldAlert className="w-4 h-4 text-orange-400" />
              </div>
              <span className="text-2xl font-bold font-mono text-slate-100">
                {context.summary?.total_alerts ?? context.correlated_alerts?.length ?? 0}
              </span>
            </div>

            <div className="p-4 rounded-lg bg-surface-200 border border-slate-800">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-xs font-mono uppercase">Incident Cases</span>
                <AlertOctagon className="w-4 h-4 text-red-400" />
              </div>
              <span className="text-2xl font-bold font-mono text-slate-100">
                {context.summary?.total_incidents ?? context.correlated_incidents?.length ?? 0}
              </span>
            </div>

            <div className="p-4 rounded-lg bg-surface-200 border border-slate-800">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-xs font-mono uppercase">Correlated IOCs</span>
                <BookOpen className="w-4 h-4 text-cyan-400" />
              </div>
              <span className="text-2xl font-bold font-mono text-slate-100">
                {context.summary?.total_indicators ?? context.correlated_indicators?.length ?? 0}
              </span>
            </div>
          </div>

          {/* Timeline & Entities Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Unified Chronological Timeline */}
            <Card
              header={
                <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Chronological Entity Timeline
                </span>
              }
            >
              {!context.recent_timeline?.length ? (
                <p className="text-xs font-mono text-slate-500 text-center py-8">
                  No timeline entries correlated with this anchor entity.
                </p>
              ) : (
                <div className="space-y-3 font-mono text-xs max-h-96 overflow-y-auto">
                  {context.recent_timeline.map((item: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-3 rounded bg-surface-300/60 border border-slate-800 flex flex-col gap-1"
                    >
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span className="font-semibold text-blue-400 uppercase">
                          {item.entity_type}
                        </span>
                        <span>{formatDate(item.timestamp)}</span>
                      </div>
                      <span className="text-slate-200 font-semibold">{item.title}</span>
                      {item.summary && (
                        <span className="text-slate-400 text-[11px]">{item.summary}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Correlated Alerts List */}
            <Card
              header={
                <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Correlated Alerts ({context.correlated_alerts?.length || 0})
                </span>
              }
            >
              {!context.correlated_alerts?.length ? (
                <p className="text-xs font-mono text-slate-500 text-center py-8">
                  No alerts correlated with this entity.
                </p>
              ) : (
                <div className="space-y-2.5 font-mono text-xs max-h-96 overflow-y-auto">
                  {context.correlated_alerts.map((a: any) => (
                    <Link
                      key={a.id}
                      href={`/alerts/${a.id}`}
                      className="block p-3 rounded bg-surface-300/60 border border-slate-800 hover:border-slate-700 transition-colors"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-semibold text-slate-100 hover:text-blue-400 truncate">
                          {a.title}
                        </span>
                        <Badge variant="severity" severity={a.severity} />
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span>Rule: {a.rule_name || a.rule_id}</span>
                        <span>{formatTimeAgo(a.created_at)}</span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </Card>
          </div>
        </div>
      )}

      {!isLoading && !context && !error && (
        <div className="text-center py-16 border border-dashed border-slate-800 rounded-lg bg-surface-300/20">
          <Search className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-300 font-mono">
            No Active Investigation Anchor
          </h3>
          <p className="text-xs text-slate-500 font-mono mt-1 max-w-md mx-auto">
            Select an anchor entity (IP address, user account, or alert identifier) and execute correlation to analyze cross-entity security context.
          </p>
        </div>
      )}
    </div>
  );
}
