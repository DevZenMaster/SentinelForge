import React from 'react';
import { cn, getSeverityClasses, getStatusClasses } from '@/lib/utils';

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?:
    | 'severity'
    | 'status'
    | 'default'
    | 'outline'
    | 'success'
    | 'warning'
    | 'danger'
    | 'neutral'
    | 'primary';
  severity?: string;
  status?: string;
  dot?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  className,
  variant = 'default',
  severity,
  status,
  dot = false,
  ...props
}) => {
  if (variant === 'severity' && severity) {
    const { badge, dot: dotColor } = getSeverityClasses(severity);
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium font-mono uppercase tracking-wide',
          badge,
          className
        )}
        {...props}
      >
        <span className={cn('h-1.5 w-1.5 rounded-full', dotColor)} />
        {children || severity}
      </span>
    );
  }

  if (variant === 'status' && status) {
    const statusClasses = getStatusClasses(status);
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium font-mono uppercase tracking-wide',
          statusClasses,
          className
        )}
        {...props}
      >
        {dot && <span className="h-1.5 w-1.5 rounded-full bg-current opacity-75" />}
        {children || status.replace('_', ' ')}
      </span>
    );
  }

  const variantStyles: Record<string, string> = {
    success: 'bg-emerald-950/60 text-emerald-300 border border-emerald-800',
    warning: 'bg-amber-950/60 text-amber-300 border border-amber-800',
    danger: 'bg-red-950/60 text-red-300 border border-red-800',
    neutral: 'bg-surface-100 text-slate-400 border border-slate-700',
    primary: 'bg-blue-950/60 text-blue-300 border border-blue-800',
    outline: 'bg-transparent text-slate-300 border border-slate-700',
    default: 'bg-surface-100 text-slate-300 border border-border-subtle',
  };

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium font-mono',
        variantStyles[variant] || variantStyles.default,
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
};
