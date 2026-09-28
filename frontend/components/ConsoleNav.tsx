"use client";
import {
  LayoutGrid,
  Send,
  Inbox,
  ScanLine,
  Layers3,
  KeyRound,
} from "lucide-react";
export type ConsoleTab =
  | "overview"
  | "dispatch"
  | "inbox"
  | "forensics"
  | "ledger"
  | "vault";
export const consoleTabs = [
  { id: "overview", label: "Overview", icon: LayoutGrid },
  { id: "dispatch", label: "Send document", icon: Send },
  { id: "inbox", label: "Secure inbox", icon: Inbox },
  { id: "ledger", label: "Activity ledger", icon: Layers3 },
  { id: "forensics", label: "Investigations", icon: ScanLine },
  { id: "vault", label: "Key vault", icon: KeyRound },
] as const;
export function ConsoleNav({
  activeTab,
  onTabChange,
  logCount = 0,
}: {
  activeTab: ConsoleTab;
  onTabChange: (tab: ConsoleTab) => void;
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
        {consoleTabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={`nav-item ${activeTab === id ? "active" : ""}`}
            aria-current={activeTab === id ? "page" : undefined}
            onClick={() => onTabChange(id)}
          >
            <Icon size={17} strokeWidth={1.6} />
            <span>{label}</span>
            {id === "ledger" && logCount > 0 && <small>{logCount}</small>}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <span>Document security workspace</span>
      </div>
    </aside>
  );
}
