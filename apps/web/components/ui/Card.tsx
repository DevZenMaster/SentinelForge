import React from 'react';
import { cn } from '@/lib/utils';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  header?: React.ReactNode;
  footer?: React.ReactNode;
}

export const Card: React.FC<CardProps> = ({
  className,
  header,
  footer,
  children,
  ...props
}) => {
  return (
    <div
      className={cn(
        'bg-surface-200 border border-slate-800/80 rounded-lg shadow-sm overflow-hidden',
        className
      )}
      {...props}
    >
      {header && (
        <div className="px-5 py-3.5 border-b border-slate-800 bg-surface-300/60 font-medium text-slate-200 flex items-center justify-between">
          {header}
        </div>
      )}
      <div className="p-5">{children}</div>
      {footer && (
        <div className="px-5 py-3 border-t border-slate-800 bg-surface-300/40 text-xs text-slate-400">
          {footer}
        </div>
      )}
    </div>
  );
};
