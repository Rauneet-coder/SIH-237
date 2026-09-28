"use client";
import {
  LayoutGrid,
  Send,
  Inbox,
  ScanLine,
  Layers3,
  KeyRound,
} from "lucide-react";
import Link from "next/link";
export type ConsoleTab =
  | "overview"
  | "dispatch"
  | "inbox"
  | "forensics"
  | "ledger"
  | "vault";
export const consoleTabs = [
  { id: "overview", href: "/", label: "Overview", icon: LayoutGrid },
  { id: "dispatch", href: "/send", label: "Send document", icon: Send },
  { id: "inbox", href: "/inbox", label: "Secure inbox", icon: Inbox },
  { id: "ledger", href: "/ledger", label: "Activity ledger", icon: Layers3 },
  {
    id: "forensics",
    href: "/investigations",
    label: "Investigations",
    icon: ScanLine,
  },
  { id: "vault", href: "/keys", label: "Key vault", icon: KeyRound },
] as const;
export function ConsoleNav({
  activeTab,
  logCount = 0,
}: {
  activeTab: ConsoleTab;
  logCount?: number;
}) {
  return (
    <aside className="sidebar">
      <a className="brand" href="/" aria-label="Pramaan home">
        <span className="brand-symbol">
          p<span>•</span>
        </span>
        <span>
          pramaan<span className="brand-caption">Secure document sharing</span>
        </span>
      </a>
      <div className="workspace-label">
        <span className="workspace-icon">D</span>
        <div>
          Defence workspace<small>SIH 2026 · Project 26237</small>
        </div>
      </div>
      <div className="nav-label">WORKSPACE</div>
      <nav aria-label="Workspace navigation">
        {consoleTabs.map(({ id, label, icon: Icon, href }) => (
          <Link
            href={href}
            key={id}
            className={`nav-item ${activeTab === id ? "active" : ""}`}
            aria-current={activeTab === id ? "page" : undefined}
          >
            <Icon size={17} strokeWidth={1.6} />
            <span>{label}</span>
            {id === "ledger" && logCount > 0 && <small>{logCount}</small>}
          </Link>
        ))}
      </nav>
      <div className="sidebar-footer">
        <span>Document security workspace</span>
      </div>
    </aside>
  );
}
