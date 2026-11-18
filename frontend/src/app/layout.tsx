import React from 'react';
import './globals.css';
import AppShell from '@/components/AppShell';

export const metadata = {
  title: 'AEGIS - Security Platform',
  description: 'Verify ownership, scan websites, and review security findings.',
  icons: {
    icon: '/favicon.ico',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#060911] text-slate-100 antialiased font-sans min-h-screen">
        <AppShell>
          {children}
        </AppShell>
      </body>
    </html>
  );
}
