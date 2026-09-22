'use client';

import React from 'react';
import { LayoutDashboard, Send, Inbox, Search, Database, Key } from 'lucide-react';

export type ConsoleTab = 'overview' | 'dispatch' | 'inbox' | 'forensics' | 'ledger' | 'vault';

interface ConsoleNavProps {
  activeTab: ConsoleTab;
  onTabChange: (tab: ConsoleTab) => void;
  documentCount?: number;
  inboxCount?: number;
  logCount?: number;
}

export function ConsoleNav({
  activeTab,
  onTabChange,
  documentCount = 0,
  inboxCount = 0,
  logCount = 0
}: ConsoleNavProps) {
  const tabs = [
    {
      id: 'overview' as ConsoleTab,
      label: 'OVERVIEW',
      icon: LayoutDashboard,
      badge: 'TELEMETRY'
    },
    {
      id: 'dispatch' as ConsoleTab,
      label: 'ENCRYPT & DISPATCH',
      icon: Send,
      badge: 'SENDER / ADMIN'
    },
    {
      id: 'inbox' as ConsoleTab,
      label: 'SECURE INBOX',
      icon: Inbox,
      badge: 'RECIPIENT'
    },
    {
      id: 'forensics' as ConsoleTab,
      label: 'TRAITOR TRACING',
      icon: Search,
      badge: 'INVESTIGATOR'
    },
    {
      id: 'ledger' as ConsoleTab,
      label: 'PROVENANCE LEDGER',
      icon: Database,
      badge: logCount > 0 ? `#${logCount} AUDIT` : 'AUDITOR'
    },
    {
      id: 'vault' as ConsoleTab,
      label: 'KEY VAULT',
      icon: Key,
      badge: 'IDENTITY'
    }
  ];

  return (
    <div style={{ borderBottom: '1px solid var(--border-medium)', background: 'var(--bg-secondary)' }}>
      <div className="container-full">
        <nav style={{ display: 'flex', gap: '4px', overflowX: 'auto' }}>
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '14px 18px',
                  background: 'transparent',
                  border: 'none',
                  borderBottom: isActive ? '2px solid #ffffff' : '2px solid transparent',
                  color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
                  fontSize: '11px',
                  fontWeight: 600,
                  letterSpacing: '0.08em',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  whiteSpace: 'nowrap'
                }}
                onMouseEnter={(e) => {
                  if (!isActive) e.currentTarget.style.color = 'var(--text-secondary)';
                }}
                onMouseLeave={(e) => {
                  if (!isActive) e.currentTarget.style.color = 'var(--text-muted)';
                }}
              >
                <Icon size={14} strokeWidth={isActive ? 2.5 : 1.8} />
                <span>{tab.label}</span>
                {tab.badge !== null && (
                  <span
                    className="badge font-mono"
                    style={{
                      fontSize: '9px',
                      padding: '1px 5px',
                      background: isActive ? '#ffffff' : 'var(--bg-elevated)',
                      color: isActive ? '#000000' : 'var(--text-secondary)',
                      borderColor: isActive ? '#ffffff' : 'var(--border-strong)'
                    }}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </div>
  );
}
