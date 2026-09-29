import type { Metadata } from "next";
import "./globals.css";
import { WorkspaceShell } from "../components/WorkspaceShell";
import { ThemeProvider } from "../components/ThemeProvider";

export const metadata: Metadata = {
  title: "Ledgr.io — Document Provenance Workspace",
  description:
    "Ministry of Defence // Multi-Recipient Hybrid Encryption & Immutable Decryption Provenance Ledger",
  icons: {
    icon: "/icon.svg",
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
      </head>
      <body className="engineering-grid">
        <ThemeProvider>
          <WorkspaceShell>{children}</WorkspaceShell>
        </ThemeProvider>
      </body>
    </html>
  );
}
