'use client';

import React, { useState } from 'react';
import { useAuth, DEMO_PROFILES } from '../lib/authContext';
import { Shield, User as UserIcon, LogOut, ChevronDown, CheckCircle, Terminal, Key } from 'lucide-react';

interface HeaderProps {
  chainHeight?: number;
  isChainValid?: boolean;
}

export function Header({ chainHeight = 0, isChainValid = true }: HeaderProps) {
  const { user, logout, quickSwitchUser, cachedPrivateKey } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [switching, setSwitching] = useState(false);

  const handleSwitch = async (profile: typeof DEMO_PROFILES[0]) => {
    setSwitching(true);
    try {
      await quickSwitchUser(profile);
      setDropdownOpen(false);
    } finally {
      setSwitching(false);
    }
  };

  return (
    <header className="telemetry-bar">
      <div className="container-full" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: '60px' }}>
        
        {/* Left: Tactical Brand & Identity */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '36px',
            height: '36px',
            background: '#18181b',
            border: '1px solid #3f3f46',
            color: '#ffffff',
            borderRadius: 'var(--radius-xs)'
          }}>
            <Shield size={18} fill="#ffffff" color="#ffffff" strokeWidth={1} />
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="font-bold text-sm tracking-wide text-primary">SIH26237</span>
              <span className="text-dim text-xs">/</span>
              <span className="uppercase-track text-secondary">MINISTRY OF DEFENCE</span>
            </div>
            <div className="text-xs text-muted" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span>CRYPTOGRAPHIC ATTRIBUTION & PROVENANCE SYSTEM</span>
            </div>
          </div>
        </div>

        {/* Center: Real-time Security Telemetry Pills */}
        {user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className="badge">
              <span className="status-dot status-dot-green"></span>
              <span>CIPHER: AES-256-GCM</span>
            </div>

            <div className="badge">
              <span className="status-dot status-dot-white"></span>
              <span>TARDOS: 256-BIT CODEWORD</span>
            </div>

            <div className="badge">
              <span className={`status-dot ${isChainValid ? 'status-dot-green' : 'status-dot-red'}`}></span>
              <span>LEDGER: BLOCKS #{chainHeight}</span>
            </div>
          </div>
        )}

        {/* Right: Active Role / Quick Switcher & User Profile */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          
          {user ? (
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className="btn btn-secondary btn-sm font-mono"
                style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                disabled={switching}
              >
                <span className="status-dot status-dot-green"></span>
                <span>{user.username.toUpperCase()}</span>
                <span className="badge badge-white text-xs" style={{ padding: '1px 5px' }}>
                  {user.role}
                </span>
                {cachedPrivateKey && (
                  <span title="RSA Private Key Loaded" style={{ display: 'inline-flex' }}>
                    <Key size={12} color="#34d399" />
                  </span>
                )}
                <ChevronDown size={14} />
              </button>

              {dropdownOpen && (
                <>
                  {/* Click-away overlay to dismiss dropdown */}
                  <div
                    style={{ position: 'fixed', inset: 0, zIndex: 90 }}
                    onClick={() => setDropdownOpen(false)}
                  />
                  <div
                    style={{
                      position: 'absolute',
                      top: '100%',
                      right: 0,
                      marginTop: '6px',
                      width: '300px',
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: 'var(--radius-xs)',
                      boxShadow: '0 8px 24px rgba(0,0,0,0.8)',
                      zIndex: 100,
                      padding: '8px'
                    }}
                  >
                    <div className="uppercase-track text-dim text-xs" style={{ padding: '6px 8px', borderBottom: '1px solid var(--border-subtle)' }}>
                      Operational Command Officer Profiles
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', margin: '6px 0' }}>
                      {DEMO_PROFILES.map((p) => {
                        const isActive = user.username === p.username;
                        return (
                          <button
                            key={p.username}
                            onClick={() => handleSwitch(p)}
                            style={{
                              display: 'flex',
                              flexDirection: 'column',
                              alignItems: 'flex-start',
                              padding: '8px',
                              background: isActive ? 'var(--bg-elevated)' : 'transparent',
                              border: 'none',
                              borderRadius: 'var(--radius-xs)',
                              cursor: 'pointer',
                              textAlign: 'left',
                              color: 'inherit',
                              transition: 'background 0.15s'
                            }}
                            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-elevated)')}
                            onMouseLeave={(e) => (e.currentTarget.style.background = isActive ? 'var(--bg-elevated)' : 'transparent')}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                              <span className="font-semibold text-xs text-primary">{p.name}</span>
                              <span className="badge text-xs" style={{ fontSize: '9px', padding: '1px 4px' }}>{p.role}</span>
                            </div>
                            <span className="text-xs text-muted" style={{ fontSize: '10px', marginTop: '2px' }}>{p.description}</span>
                          </button>
                        );
                      })}
                    </div>

                    <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
                      <button
                        onClick={() => {
                          logout();
                          setDropdownOpen(false);
                        }}
                        className="btn btn-danger btn-sm"
                        style={{ width: '100%', justifyContent: 'center' }}
                      >
                        <LogOut size={12} />
                        <span>DISCONNECT TERMINAL</span>
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="badge badge-warning">NOT CONNECTED</span>
            </div>
          )}

        </div>

      </div>
    </header>
  );
}
