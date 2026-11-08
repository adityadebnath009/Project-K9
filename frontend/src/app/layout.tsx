import type { Metadata } from 'next';
import './globals.css';
import { Navbar } from '@/components/Navbar';

export const metadata: Metadata = {
  title: 'K9 Sentinel AI — Digital Trust & Threat Intelligence',
  description:
    'Instant, evidence-grounded threat detection. Unmask phishing links, compromised digital certificates, and payment scams before they do damage.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" data-type="software" className="dark" suppressHydrationWarning>
      <head>
        <meta name="page-type" content="software" />
        <meta name="site-kind" content="software" />
      </head>
      <body className="font-sans bg-[#09090b] text-zinc-100 min-h-screen antialiased selection:bg-zinc-800 selection:text-sky-400" suppressHydrationWarning>
        <Navbar />
        <main className="min-h-[calc(100vh-64px)]">
          {children}
        </main>
      </body>
    </html>
  );
}
