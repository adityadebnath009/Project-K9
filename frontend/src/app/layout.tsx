import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'K9-SENTINEL | Threat Intelligence & Cryptographic CA Auditor',
  description:
    'Defense-grade cryptographic X.509 CA auditor, eMudhra scalar d=4 flaw inspector, typosquatting detector, and collaborative threat intelligence pipeline.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="font-sans bg-ground text-zinc-100 min-h-screen antialiased selection:bg-zinc-800 selection:text-emerald-400" suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
