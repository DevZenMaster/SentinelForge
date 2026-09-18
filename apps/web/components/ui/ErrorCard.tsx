'use client';

import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Button } from './Button';
import { cn } from '@/lib/utils';
import { ConcurrencyConflictError } from '@/lib/api/client';

interface ErrorCardProps {
  error: Error | string | null;
  onRetry?: () => void;
  className?: string;
}

export const ErrorCard: React.FC<ErrorCardProps> = ({ error, onRetry, className }) => {
  if (!error) return null;

  const isConflict =
    error instanceof ConcurrencyConflictError ||
    (typeof error === 'string' && error.toLowerCase().includes('concurrency')) ||
    (typeof error === 'string' && error.includes('409'));

  const errorMessage =
    typeof error === 'string'
      ? error
      : error.message || 'An unexpected error occurred while communicating with the security engine.';

  return (
    <div
      role="alert"
      className={cn(
        'p-4 rounded-lg border flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between',
        isConflict
          ? 'bg-amber-950/40 border-amber-800/80 text-amber-200'
          : 'bg-red-950/40 border-red-800/80 text-red-200',
        className
      )}
    >
      <div className="flex gap-3 items-start">
        <AlertTriangle
          className={cn(
            'w-5 h-5 flex-shrink-0 mt-0.5',
            isConflict ? 'text-amber-400' : 'text-red-400'
          )}
        />
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider">
            {isConflict ? 'Optimistic Concurrency Conflict (HTTP 409)' : 'Security Error'}
          </div>
          <div className="text-xs mt-0.5 opacity-90 font-mono">{errorMessage}</div>
          {isConflict && (
            <div className="text-[11px] mt-1 text-amber-300/80">
              This record was modified by another analyst or automated engine transition. Please refresh to load the latest state before retrying your action.
            </div>
          )}
        </div>
      </div>
      {onRetry && (
        <Button
          size="sm"
          variant={isConflict ? 'primary' : 'outline'}
          onClick={onRetry}
          className="flex-shrink-0 text-xs gap-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          {isConflict ? 'Reload Latest Version' : 'Retry'}
        </Button>
      )}
    </div>
  );
};
