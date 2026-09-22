'use client';

import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth, DEMO_PROFILES } from '../lib/authContext';
import { Header } from '../components/Header';
import { ConsoleNav, ConsoleTab } from '../components/ConsoleNav';
import { OverviewConsole } from '../components/consoles/OverviewConsole';
import { DispatchConsole } from '../components/consoles/DispatchConsole';
import { InboxConsole } from '../components/consoles/InboxConsole';
import { ForensicsConsole } from '../components/consoles/ForensicsConsole';
import { LedgerConsole } from '../components/consoles/LedgerConsole';
import { KeyVaultConsole } from '../components/consoles/KeyVaultConsole';
import { api } from '../lib/api';
import { Shield, Lock, Key, ArrowRight, UserPlus, LogIn, AlertCircle } from 'lucide-react';

function DashboardContent() {
  const { user, token, login, register, quickSwitchUser, isLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<ConsoleTab>('overview');
  const [chainHeight, setChainHeight] = useState(0);
  const [isChainValid, setIsChainValid] = useState(true);

  // Auth Modal State
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('recipient');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSubmitting, setAuthSubmitting] = useState(false);

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

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSubmitting(true);
    try {
      if (authMode === 'login') {
        await login(username, password);
      } else {
        await register(username, email, password, role);
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

      {/* Auth Gate: If not authenticated, show Tactical Operational Terminal Gate */}
      {!user ? (
        <main className="container-full" style={{ padding: '40px 24px', flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ width: '100%', maxWidth: '880px', display: 'grid', gridTemplateColumns: 'minmax(320px, 1.1fr) minmax(300px, 1fr)', gap: '32px' }}>
            
            {/* Left: Quick Access Demo Profiles */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
                <Shield size={18} className="text-secondary" />
                <span className="uppercase-track text-primary font-bold">1-Click Tactical Profiles (Instant Evaluation)</span>
              </div>

              <p className="text-secondary text-xs">
                Select a pre-configured defence terminal role to instantly access and evaluate the cryptographic pipeline:
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {DEMO_PROFILES.map((p) => (
                  <button
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
            onTabChange={setActiveTab}
            logCount={chainHeight}
          />

          <main className="container-full" style={{ padding: '24px', flex: 1 }}>
            {activeTab === 'overview' && <OverviewConsole onNavigate={setActiveTab} />}
            {activeTab === 'dispatch' && <DispatchConsole onSuccess={refreshLedgerStatus} />}
            {activeTab === 'inbox' && <InboxConsole />}
            {activeTab === 'forensics' && <ForensicsConsole />}
            {activeTab === 'ledger' && <LedgerConsole />}
            {activeTab === 'vault' && <KeyVaultConsole />}
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
