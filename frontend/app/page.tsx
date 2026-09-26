'use client';

import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth, COMMAND_OFFICERS } from '../lib/authContext';
import { Header } from '../components/Header';
import { ConsoleNav, ConsoleTab } from '../components/ConsoleNav';
import { OverviewConsole } from '../components/consoles/OverviewConsole';
import { DispatchConsole } from '../components/consoles/DispatchConsole';
import { InboxConsole } from '../components/consoles/InboxConsole';
import { ForensicsConsole } from '../components/consoles/ForensicsConsole';
import { LedgerConsole } from '../components/consoles/LedgerConsole';
import { KeyVaultConsole } from '../components/consoles/KeyVaultConsole';
import { api } from '../lib/api';
import { Shield, Lock, Key, ArrowRight, UserPlus, LogIn, AlertCircle, Download, Check } from 'lucide-react';

function DashboardContent() {
  const { user, token, login, register, quickSwitchUser, isLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<ConsoleTab>('overview');
  const [chainHeight, setChainHeight] = useState(0);
  const [isChainValid, setIsChainValid] = useState(true);
  const [consoleKey, setConsoleKey] = useState(0);

  // Auth Modal State
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('recipient');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [newOfficerKey, setNewOfficerKey] = useState<{ username: string; privateKey: string } | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  // Poll provenance height & validity
  const refreshLedgerStatus = async () => {
    try {
      const res = await api.verifyChain();
      setChainHeight(res.report.totalBlocks);
      setIsChainValid(res.report.valid);
    } catch {
      // Ignored if server is starting
    }
  };

  useEffect(() => {
    refreshLedgerStatus();
    const interval = setInterval(refreshLedgerStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  // Tab switch with remount for entry animation
  const handleTabChange = (tab: ConsoleTab) => {
    setActiveTab(tab);
    setConsoleKey(k => k + 1);
  };

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSubmitting(true);
    try {
      if (authMode === 'login') {
        await login(username, password);
      } else {
        const privKey = await register(username, email, password, role);
        setNewOfficerKey({ username, privateKey: privKey });
        await login(username, password);
      }
    } catch (err: any) {
      setAuthError(err.message || 'Authentication failed.');
    } finally {
      setAuthSubmitting(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* Tactical Telemetry Header */}
      <Header chainHeight={chainHeight} isChainValid={isChainValid} />

      {/* New Officer Key Generated Dialog */}
      {newOfficerKey && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.85)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div className="card" style={{ maxWidth: '580px', width: '100%', border: '1px solid #34d399', boxShadow: '0 12px 32px rgba(0,0,0,0.9)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              <Key size={20} color="#34d399" />
              <span className="font-bold text-sm text-primary uppercase-track">
                OFFICER CRYPTOGRAPHIC KEYPAIR GENERATED
              </span>
            </div>

            <p className="text-secondary text-xs" style={{ marginBottom: '14px', lineHeight: 1.6 }}>
              A fresh 2048-bit RSA keypair has been generated for officer <strong className="text-primary">{newOfficerKey.username}</strong>. The public key is stored on the ledger node. The private key below is loaded into your terminal session memory.
            </p>

            <div className="hex-box font-mono" style={{ fontSize: '10px', maxHeight: '140px', marginBottom: '16px' }}>
              {newOfficerKey.privateKey}
            </div>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(newOfficerKey.privateKey);
                  setCopiedKey(true);
                  setTimeout(() => setCopiedKey(false), 2000);
                }}
                className="btn btn-secondary btn-sm"
              >
                {copiedKey ? <Check size={12} color="#34d399" /> : <Key size={12} />}
                <span>{copiedKey ? 'COPIED TO CLIPBOARD' : 'COPY PRIVATE KEY'}</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  const blob = new Blob([newOfficerKey.privateKey], { type: 'application/x-pem-file' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `${newOfficerKey.username}_private_key.pem`;
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                }}
                className="btn btn-primary btn-sm"
              >
                <Download size={12} />
                <span>DOWNLOAD .PEM KEY FILE</span>
              </button>
              <button
                type="button"
                onClick={() => setNewOfficerKey(null)}
                className="btn btn-secondary btn-sm"
              >
                <span>CONTINUE TO WORKSPACE</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Auth Gate */}
      {!user ? (
        <main className="container-full" style={{ padding: '40px 24px', flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ width: '100%', maxWidth: '880px', display: 'grid', gridTemplateColumns: 'minmax(320px, 1.1fr) minmax(300px, 1fr)', gap: '32px' }}>
            
            {/* Left: Pre-Provisioned Command Terminals */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
                <Shield size={18} className="text-secondary" />
                <span className="uppercase-track text-primary font-bold">Active Command Terminals</span>
              </div>

              <p className="text-secondary text-xs">
                Select an operational military account to connect and operate the cryptographic pipeline:
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {COMMAND_OFFICERS.map((p) => (
                  <button
                    type="button"
                    key={p.username}
                    onClick={() => quickSwitchUser(p)}
                    className="card"
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '12px 14px',
                      cursor: 'pointer',
                      textAlign: 'left',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border-medium)',
                      color: 'inherit',
                      transition: 'all 0.15s ease'
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = '#ffffff';
                      e.currentTarget.style.background = 'var(--bg-elevated)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = 'var(--border-medium)';
                      e.currentTarget.style.background = 'var(--bg-secondary)';
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="font-semibold text-xs text-primary">{p.name}</span>
                        <span className="badge text-xs" style={{ fontSize: '9px', padding: '1px 5px' }}>{p.role}</span>
                      </div>
                      <div className="text-muted text-xs" style={{ fontSize: '11px', marginTop: '2px' }}>
                        {p.description}
                      </div>
                    </div>
                    <ArrowRight size={14} className="text-secondary" />
                  </button>
                ))}
              </div>
            </div>

            {/* Right: Manual Login / Register Form */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px', marginBottom: '16px' }}>
                <span className="uppercase-track text-primary font-bold">
                  {authMode === 'login' ? 'Terminal Authentication' : 'Create Identity & RSA Key'}
                </span>
                <div style={{ display: 'flex', gap: '4px' }}>
                  <button
                    type="button"
                    onClick={() => setAuthMode('login')}
                    className={`btn btn-sm ${authMode === 'login' ? 'btn-primary' : 'btn-secondary'}`}
                  >
                    Login
                  </button>
                  <button
                    type="button"
                    onClick={() => setAuthMode('register')}
                    className={`btn btn-sm ${authMode === 'register' ? 'btn-primary' : 'btn-secondary'}`}
                  >
                    Register
                  </button>
                </div>
              </div>

              {authError && (
                <div className="badge badge-danger" style={{ display: 'flex', width: '100%', padding: '8px 12px', marginBottom: '16px' }}>
                  <AlertCircle size={14} />
                  <span>{authError}</span>
                </div>
              )}

              <form onSubmit={handleAuthSubmit}>
                <div className="input-group">
                  <label className="input-label">Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="e.g. col_sharma"
                    className="input-text font-mono"
                    required
                  />
                </div>

                {authMode === 'register' && (
                  <>
                    <div className="input-group">
                      <label className="input-label">Official Email</label>
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="e.g. officer@mod.gov.in"
                        className="input-text font-mono"
                        required
                      />
                    </div>

                    <div className="input-group">
                      <label className="input-label">Role Classification</label>
                      <select
                        value={role}
                        onChange={(e) => setRole(e.target.value)}
                        className="input-select font-mono"
                      >
                        <option value="sender">Sender (Encapsulation Authority)</option>
                        <option value="recipient">Recipient (Command Unit)</option>
                        <option value="investigator">Investigator (Forensics / Traitor Tracing)</option>
                        <option value="admin">Auditor General (Ledger Inspector)</option>
                      </select>
                    </div>
                  </>
                )}

                <div className="input-group">
                  <label className="input-label">Security Passphrase</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="input-text"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={authSubmitting}
                  className="btn btn-primary"
                  style={{ width: '100%', marginTop: '12px', padding: '12px' }}
                >
                  {authMode === 'login' ? <LogIn size={14} /> : <UserPlus size={14} />}
                  <span>{authSubmitting ? 'AUTHENTICATING...' : authMode === 'login' ? 'ENTER SECURE TERMINAL' : 'GENERATE RSA KEYPAIR & REGISTER'}</span>
                </button>
              </form>
            </div>

          </div>
        </main>
      ) : (
        /* Authenticated Workspace */
        <>
          <ConsoleNav
            activeTab={activeTab}
            onTabChange={handleTabChange}
            logCount={chainHeight}
          />

          <main className="container-full" style={{ padding: '24px', flex: 1 }}>
            <div key={consoleKey} className="console-enter">
              {activeTab === 'overview' && <OverviewConsole onNavigate={handleTabChange} />}
              {activeTab === 'dispatch' && <DispatchConsole onSuccess={refreshLedgerStatus} />}
              {activeTab === 'inbox' && <InboxConsole />}
              {activeTab === 'forensics' && <ForensicsConsole />}
              {activeTab === 'ledger' && <LedgerConsole />}
              {activeTab === 'vault' && <KeyVaultConsole />}
            </div>
          </main>
        </>
      )}

      {/* Footer Status Bar */}
      <footer style={{ borderTop: '1px solid var(--border-medium)', background: 'var(--bg-secondary)', padding: '12px 0' }}>
        <div className="container-full" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div className="font-mono text-xs text-muted" style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="status-dot status-dot-green"></span>
            <span>NODE ONLINE: EXPRESS:8000 // MONGODB:27017</span>
            <span className="text-dim">|</span>
            <span>SPEC: SIH26237 DEFENCE CYBER ATTRIBUTION</span>
          </div>

          <div className="font-mono text-xs text-secondary" style={{ fontSize: '11px' }}>
            STRICT MONOCHROMATIC TACTICAL CONSOLE // ZERO THIRD-PARTY CRYPTO
          </div>
        </div>
      </footer>

    </div>
  );
}

export default function Home() {
  return (
    <AuthProvider>
      <DashboardContent />
    </AuthProvider>
  );
}
