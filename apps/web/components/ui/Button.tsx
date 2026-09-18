import React from 'react';
import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'secondary',
      size = 'md',
      isLoading = false,
      disabled,
      children,
      ...props
    },
    ref
  ) => {
    const baseStyles =
      'inline-flex items-center justify-center font-medium rounded transition-colors focus:outline-none focus:ring-1 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed select-none';

    const variants = {
      primary: 'bg-primary-600 hover:bg-primary-500 text-white shadow-sm border border-primary-500',
      secondary:
        'bg-surface-100 hover:bg-surface-50 text-slate-200 border border-slate-700/80 shadow-sm',
      danger:
        'bg-red-950/70 hover:bg-red-900 text-red-300 border border-red-800/80 shadow-sm',
      ghost: 'hover:bg-surface-100 text-slate-300 hover:text-white',
      outline:
        'border border-slate-700 hover:border-slate-600 text-slate-300 hover:text-white bg-transparent',
    };

    const sizes = {
      sm: 'text-xs px-2.5 py-1 gap-1.5',
      md: 'text-sm px-3.5 py-1.5 gap-2',
      lg: 'text-base px-4 py-2 gap-2.5',
    };

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={cn(baseStyles, variants[variant], sizes[size], className)}
        {...props}
      >
        {isLoading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
