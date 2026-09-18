'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldAlert,
  AlertOctagon,
  Binary,
  Search,
  BookOpen,
  History,
  FileCode2,
  BarChart3,
  Webhook,
  SlidersHorizontal,
  BellRing,
  Users,
  Settings,
} from 'lucide-react';
import { useAuth } from '@/lib/auth/context';
import { cn } from '@/lib/utils';
import { Logo } from '@/components/branding/Logo';

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  requiredPermission?: string;
  badge?: string;
}

const navItems: NavItem[] = [
  {
    label: 'SOC Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
  },
  {
    label: 'Alerts & Triage',
    href: '/alerts',
    icon: ShieldAlert,
    requiredPermission: 'alerts.read',
  },
  {
    label: 'Incidents',
    href: '/incidents',
    icon: AlertOctagon,
    requiredPermission: 'incidents.read',
  },
  {
    label: 'Security Events',
    href: '/events',
    icon: Binary,
    requiredPermission: 'events.read',
  },
  {
    label: 'Investigations',
    href: '/investigations',
    icon: Search,
    requiredPermission: 'investigations.read',
  },
  {
    label: 'Detection Rules',
    href: '/detection-rules',
    icon: FileCode2,
    requiredPermission: 'detection_rules.read',
  },
  {
    label: 'Threat Intelligence',
    href: '/threat-intelligence',
    icon: BookOpen,
    requiredPermission: 'intelligence.read',
  },
  {
    label: 'Security Reports',
    href: '/reports',
    icon: BarChart3,
    requiredPermission: 'reports.read',
  },
  {
    label: 'Integrations',
    href: '/integrations',
    icon: Webhook,
    requiredPermission: 'integrations.read',
  },
  {
    label: 'Notification Policies',
    href: '/notification-policies',
    icon: SlidersHorizontal,
    requiredPermission: 'notification_policies.read',
  },
  {
    label: 'Delivery Logs',
    href: '/notifications',
    icon: BellRing,
    requiredPermission: 'notifications.read',
  },
  {
    label: 'Audit Trail',
    href: '/audit',
    icon: History,
    requiredPermission: 'audit.read',
  },
  {
    label: 'User Management',
    href: '/admin/users',
    icon: Users,
    requiredPermission: 'users.read',
  },
  {
    label: 'User Settings',
    href: '/settings',
    icon: Settings,
  },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();
  const { hasPermission, roles } = useAuth();

  return (
    <aside className="w-64 bg-surface-300 border-r border-slate-800 flex flex-col flex-shrink-0 select-none">
      {/* Brand Header */}
      <Link
        href="/dashboard"
        className="h-14 flex items-center px-4 border-b border-slate-800 bg-surface-400/50 hover:bg-surface-400/80 transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500"
        title="SentinelForge SOC Dashboard"
      >
        <Logo variant="full" size="md" className="h-10 w-auto max-w-[210px]" priority />
      </Link>

      {/* Navigation Links */}
      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          if (item.requiredPermission && !hasPermission(item.requiredPermission)) {
            return null;
          }

          const isActive =
            pathname === item.href ||
            (item.href !== '/dashboard' && pathname.startsWith(item.href));

          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded text-xs font-medium transition-colors',
                isActive
                  ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-surface-100/50'
              )}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span className="truncate">{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Footer / Role indicator */}
      <div className="p-3.5 border-t border-slate-800 bg-surface-400/40 text-[11px] font-mono text-slate-400 flex items-center justify-between">
        <span>Active Roles:</span>
        <div className="flex gap-1 flex-wrap justify-end">
          {roles.map((r) => (
            <span
              key={r}
              className="px-1.5 py-0.5 rounded bg-surface-100 border border-slate-700 text-slate-300 text-[10px] uppercase font-mono"
            >
              {r}
            </span>
          ))}
        </div>
      </div>
    </aside>
  );
};
