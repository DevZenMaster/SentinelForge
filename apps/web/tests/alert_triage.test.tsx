import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ErrorCard } from '@/components/ui/ErrorCard';
import { ConcurrencyConflictError } from '@/lib/api/client';
import { Badge } from '@/components/ui/Badge';

describe('Alert Triage & UI Security Controls', () => {
  it('renders optimistic concurrency conflict warning when receiving HTTP 409', () => {
    const onRetry = vi.fn();
    const conflictError = new ConcurrencyConflictError('Version mismatch on alert update');

    render(<ErrorCard error={conflictError} onRetry={onRetry} />);

    expect(
      screen.getByText('Optimistic Concurrency Conflict (HTTP 409)')
    ).toBeInTheDocument();
    expect(screen.getByText(/Version mismatch on alert update/)).toBeInTheDocument();
    expect(screen.getByText('Reload Latest Version')).toBeInTheDocument();
  });

  it('renders severity badges with strictly defined accessible styles', () => {
    const { container } = render(<Badge variant="severity" severity="CRITICAL" />);
    const badge = container.querySelector('span');
    expect(badge).toHaveTextContent('CRITICAL');
    expect(badge?.className).toContain('text-red-400');
  });

  it('escapes and renders potentially malicious script content safely as text', () => {
    const maliciousNote = "<script>alert('xss')</script>";
    const { container } = render(
      <div data-testid="triage-note" className="text-xs text-slate-200 font-mono">
        {maliciousNote}
      </div>
    );

    const el = screen.getByTestId('triage-note');
    expect(el.textContent).toBe("<script>alert('xss')</script>");
    expect(container.querySelector('script')).toBeNull();
  });
});
