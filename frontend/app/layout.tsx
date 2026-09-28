import type { Metadata } from "next";
import "./globals.css";
import { WorkspaceShell } from "../components/WorkspaceShell";
import { ThemeProvider } from "../components/ThemeProvider";

export const metadata: Metadata = {
  title: "Pramaan — Document Provenance Workspace",
  description:
    "Ministry of Defence // Multi-Recipient Hybrid Encryption & Immutable Decryption Provenance Ledger",
  icons: {
    icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">p</text></svg>',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script src="/theme.js" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="engineering-grid">
        <ThemeProvider>
          <WorkspaceShell>{children}</WorkspaceShell>
        </ThemeProvider>
      </body>
    </html>
  );
}
