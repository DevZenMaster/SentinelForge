import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { Logo } from '@/components/branding/Logo';
import LoginPage from '@/app/login/page';
import { Sidebar } from '@/components/layout/Sidebar';
import { AuthProvider } from '@/lib/auth/context';

// Mock apiClient to prevent real network calls
vi.mock('@/lib/api/client', () => ({
  apiClient: {
    get: vi.fn().mockRejectedValue(new Error('unauthenticated')),
    post: vi.fn(),
  },
}));

// Mock usePathname
vi.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
  }),
}));

describe('SentinelForge Branding & Logo Integration', () => {
  it('renders default full logo with accessible alt text and correct asset path', () => {
    render(<Logo />);
    const img = screen.getByRole('img', { name: 'SentinelForge' });
    expect(img).toBeInTheDocument();
    expect(img).toHaveAttribute('src', '/branding/logo.png');
    expect(img).toHaveAttribute('alt', 'SentinelForge');
  });

  it('renders mark variant with shield emblem asset path', () => {
    render(<Logo variant="mark" alt="SentinelForge Emblem" />);
    const img = screen.getByRole('img', { name: 'SentinelForge Emblem' });
    expect(img).toBeInTheDocument();
    expect(img).toHaveAttribute('src', '/branding/logo-mark.png');
  });

  it('wraps logo in an accessible link when href is provided', () => {
    render(<Logo href="/dashboard" alt="Navigate to Dashboard" />);
    const link = screen.getByRole('link', { name: 'Navigate to Dashboard' });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute('href', '/dashboard');
    const img = screen.getByRole('img', { name: 'Navigate to Dashboard' });
    expect(img).toBeInTheDocument();
  });

  it('applies preset sizing classes correctly', () => {
    const { rerender } = render(<Logo size="sm" />);
    let img = screen.getByRole('img');
    expect(img.className).toContain('h-8');

    rerender(<Logo size="xl" />);
    img = screen.getByRole('img');
    expect(img.className).toContain('h-[72px]');
  });

  it('renders official branding in LoginPage', () => {
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );

    const logo = screen.getByRole('img', { name: 'SentinelForge' });
    expect(logo).toBeInTheDocument();
    expect(logo).toHaveAttribute('src', '/branding/logo.png');
    expect(screen.getByText('Security Operations Center Portal')).toBeInTheDocument();
  });

  it('renders official branding in Sidebar header linking to dashboard', () => {
    render(
      <AuthProvider>
        <Sidebar />
      </AuthProvider>
    );

    const sidebarLogo = screen.getByRole('img', { name: 'SentinelForge' });
    expect(sidebarLogo).toBeInTheDocument();
    expect(sidebarLogo.closest('a')).toHaveAttribute('href', '/dashboard');
  });

  it('exports valid metadata with official favicon, apple-touch-icon, and openGraph', async () => {
    const { metadata } = await import('@/app/layout');
    expect(metadata.icons).toBeDefined();
    const icons = metadata.icons as any;
    expect(icons.icon).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ url: '/branding/favicon.ico' }),
        expect.objectContaining({ url: '/branding/favicon-32x32.png' }),
        expect.objectContaining({ url: '/branding/icon-512x512.png' }),
      ])
    );
    expect(icons.apple).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ url: '/branding/apple-touch-icon.png' }),
      ])
    );
    expect(metadata.openGraph).toEqual(
      expect.objectContaining({
        title: 'SentinelForge SOC | Security Operations Center',
        images: expect.arrayContaining([
          expect.objectContaining({ url: '/branding/logo.png' }),
        ]),
      })
    );
  });
});
