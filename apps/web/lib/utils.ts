import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateStr?: string | null): string {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      timeZone: 'UTC',
    }) + ' UTC';
  } catch {
    return dateStr;
  }
}

export function formatTimeAgo(dateStr?: string | null): string {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - d.getTime()) / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    const diffDays = Math.floor(diffHour / 24);
    return `${diffDays}d ago`;
  } catch {
    return dateStr;
  }
}

export function getSeverityClasses(severity?: string): {
  badge: string;
  dot: string;
} {
  const norm = severity?.toUpperCase();
  switch (norm) {
    case 'CRITICAL':
      return {
        badge: 'bg-red-950/60 text-red-400 border border-red-800/80',
        dot: 'bg-red-500',
      };
    case 'HIGH':
      return {
        badge: 'bg-orange-950/60 text-orange-400 border border-orange-800/80',
        dot: 'bg-orange-500',
      };
    case 'MEDIUM':
      return {
        badge: 'bg-amber-950/60 text-amber-400 border border-amber-800/80',
        dot: 'bg-amber-500',
      };
    case 'LOW':
      return {
        badge: 'bg-blue-950/60 text-blue-400 border border-blue-800/80',
        dot: 'bg-blue-500',
      };
    case 'INFO':
    default:
      return {
        badge: 'bg-slate-900/80 text-slate-300 border border-slate-700/80',
        dot: 'bg-slate-400',
      };
  }
}

export function getStatusClasses(status?: string): string {
  const norm = status?.toUpperCase();
  switch (norm) {
    case 'OPEN':
      return 'bg-red-950/50 text-red-300 border border-red-800/60';
    case 'ACKNOWLEDGED':
      return 'bg-blue-950/50 text-blue-300 border border-blue-800/60';
    case 'IN_PROGRESS':
      return 'bg-amber-950/50 text-amber-300 border border-amber-800/60';
    case 'SUPPRESSED':
      return 'bg-slate-900/60 text-slate-400 border border-slate-700/60';
    case 'RESOLVED':
      return 'bg-emerald-950/50 text-emerald-300 border border-emerald-800/60';
    case 'CLOSED':
      return 'bg-zinc-900/80 text-zinc-400 border border-zinc-700/60';
    default:
      return 'bg-slate-900/60 text-slate-400 border border-slate-700/60';
  }
}
