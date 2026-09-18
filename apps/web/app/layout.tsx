import React from 'react';
import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/lib/auth/context';
import { AppShell } from '@/components/layout/AppShell';

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'),
  title: 'SentinelForge SOC | Security Operations Center',
  description: 'Enterprise Security Operations, Detection Engineering & Incident Triage Platform',
  icons: {
    icon: [
      { url: '/branding/favicon.ico', sizes: 'any' },
      { url: '/branding/favicon-32x32.png', type: 'image/png', sizes: '32x32' },
      { url: '/branding/icon-512x512.png', type: 'image/png', sizes: '512x512' },
    ],
    apple: [
      { url: '/branding/apple-touch-icon.png', sizes: '180x180', type: 'image/png' },
    ],
  },
  openGraph: {
    title: 'SentinelForge SOC | Security Operations Center',
    description: 'Enterprise Security Operations, Detection Engineering & Incident Triage Platform',
    images: [
      {
        url: '/branding/logo.png',
        width: 790,
        height: 316,
        alt: 'SentinelForge Logo',
      },
    ],
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="font-sans antialiased bg-background text-slate-100 min-h-screen">
        <AuthProvider>
          <AppShell>{children}</AppShell>
        </AuthProvider>
      </body>
    </html>
  );
}
