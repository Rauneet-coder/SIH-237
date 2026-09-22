import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SIH26237 // Cryptographic Attribution & Provenance System',
  description: 'Ministry of Defence // Multi-Recipient Hybrid Encryption & Immutable Decryption Provenance Ledger',
  icons: {
    icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>'
  }
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="engineering-grid">{children}</body>
    </html>
  );
}
