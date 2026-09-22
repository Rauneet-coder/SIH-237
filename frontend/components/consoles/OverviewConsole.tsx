'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '../../lib/authContext';
import { api, DocumentMeta, ProvenanceLogEntry, VerificationReport } from '../../lib/api';
import { ConsoleTab } from '../ConsoleNav';
import { Shield, Send, Inbox, Search, Database, CheckCircle, AlertTriangle, ArrowRight, Lock, Key } from 'lucide-react';

interface OverviewConsoleProps {
  onNavigate: (tab: ConsoleTab) => void;
}

export function OverviewConsole({ onNavigate }: OverviewConsoleProps) {
  const { user, token, cachedPrivateKey } = useAuth();
  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [recentLogs, setRecentLogs] = useState<ProvenanceLogEntry[]>([]);
  const [auditReport, setAuditReport] = useState<VerificationReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadTelemetry() {
      try {
        const [docsRes, logsRes, verifyRes] = await Promise.all([
          token ? api.listDocuments(token).catch(() => ({ documents: [] })) : Promise.resolve({ documents: [] }),
          token ? api.listLogs({ limit: '6' }, token).catch(() => ({ total: 0, logs: [] })) : Promise.resolve({ total: 0, logs: [] }),
          api.verifyChain().catch(() => null)
        ]);

        setDocuments(docsRes.documents || []);
        setRecentLogs(logsRes.logs || []);
        if (verifyRes) setAuditReport(verifyRes.report);
      } catch (err) {
        console.error('Failed to load telemetry:', err);
      } finally {
        setLoading(false);
      }
    }

    loadTelemetry();
  }, [token]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Top Banner: Mission Directive & Identity */}
      <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span className="badge badge-white">SECURE OPERATIONAL CONSOLE</span>
            <span className="badge">PQC & HYBRID ATTRIBUTION</span>
          </div>
          <h1 className="text-xl font-bold" style={{ letterSpacing: '-0.01em' }}>
            Cryptographic Attribution & Immutable Decryption Provenance
          </h1>
          <p className="text-secondary text-sm" style={{ marginTop: '4px' }}>
            Multi-recipient AES-256-GCM + RSA-OAEP encapsulation, Tardos collusion-secure fingerprinting, and server-signed blockchain provenance.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button onClick={() => onNavigate('dispatch')} className="btn btn-primary">
            <Send size={13} />
            <span>DISPATCH DOCUMENT</span>
          </button>
          <button onClick={() => onNavigate('inbox')} className="btn btn-secondary">
            <Inbox size={13} />
            <span>OPEN INBOX</span>
          </button>
        </div>
      </div>

      {/* Telemetry Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
        
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="uppercase-track text-muted">SECURE LEDGER BLOCKS</span>
            <Database size={16} className="text-secondary" />
          </div>
          <div className="text-2xl font-bold font-mono" style={{ margin: '12px 0 4px 0' }}>
            #{auditReport ? auditReport.totalBlocks : recentLogs.length}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className={`status-dot ${auditReport?.valid ? 'status-dot-green' : 'status-dot-red'}`}></span>
            <span className="text-xs text-secondary">
              {auditReport?.valid ? 'Chain 100% Valid & Signed' : 'Verifying Ledger State...'}
            </span>
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="uppercase-track text-muted">ENCRYPTED DOCUMENTS</span>
            <Lock size={16} className="text-secondary" />
          </div>
          <div className="text-2xl font-bold font-mono" style={{ margin: '12px 0 4px 0' }}>
            {documents.length}
          </div>
          <div className="text-xs text-muted">
            AES-256-GCM + Per-Recipient RSA Wrap
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="uppercase-track text-muted">TRAITOR TRACING SHIELD</span>
            <Search size={16} className="text-secondary" />
          </div>
          <div className="text-2xl font-bold font-mono" style={{ margin: '12px 0 4px 0' }}>
            TARDOS-256
          </div>
          <div className="text-xs text-secondary" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className="status-dot status-dot-white"></span>
            <span>Cutoff p ∈ [0.15, 0.85] | Z = 20.0</span>
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="uppercase-track text-muted">RECIPIENT KEY STATUS</span>
            <Key size={16} className="text-secondary" />
          </div>
          <div className="text-2xl font-bold font-mono" style={{ margin: '12px 0 4px 0' }}>
            {cachedPrivateKey ? 'LOADED' : 'UNLOADED'}
          </div>
          <div className="text-xs text-secondary" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className={`status-dot ${cachedPrivateKey ? 'status-dot-green' : 'status-dot-amber'}`}></span>
            <span>{cachedPrivateKey ? 'Client-side RSA-2048 Ready' : 'Provide PEM to Decrypt'}</span>
          </div>
        </div>

      </div>

      {/* Operational Console Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        
        {/* Quick Launch Actions */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
            Operational Consoles
          </div>

          <div
            onClick={() => onNavigate('dispatch')}
            className="card"
            style={{ padding: '14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
          >
            <div>
              <div className="font-semibold text-sm">1. Hybrid Encrypt & Dispatch</div>
              <div className="text-xs text-muted">Multi-recipient key encapsulation with instant attribution</div>
            </div>
            <ArrowRight size={14} className="text-secondary" />
          </div>

          <div
            onClick={() => onNavigate('inbox')}
            className="card"
            style={{ padding: '14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
          >
            <div>
              <div className="font-semibold text-sm">2. Secure Decrypt & Optical Watermark</div>
              <div className="text-xs text-muted">Client-side RSA decrypt with camera-resilient optical watermarking</div>
            </div>
            <ArrowRight size={14} className="text-secondary" />
          </div>

          <div
            onClick={() => onNavigate('forensics')}
            className="card"
            style={{ padding: '14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
          >
            <div>
              <div className="font-semibold text-sm">3. Tardos Traitor Tracing & Simulation</div>
              <div className="text-xs text-muted">Accuse colluding traitors and simulate coalition attacks</div>
            </div>
            <ArrowRight size={14} className="text-secondary" />
          </div>

          <div
            onClick={() => onNavigate('ledger')}
            className="card"
            style={{ padding: '14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
          >
            <div>
              <div className="font-semibold text-sm">4. Immutable Blockchain Explorer</div>
              <div className="text-xs text-muted">Audit sequence hashes and verify server authority signatures</div>
            </div>
            <ArrowRight size={14} className="text-secondary" />
          </div>
        </div>

        {/* Live Provenance Stream */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
            <span className="uppercase-track text-muted">Latest Provenance Ledger Blocks</span>
            <button onClick={() => onNavigate('ledger')} className="btn btn-secondary btn-sm text-xs">
              VIEW FULL CHAIN
            </button>
          </div>

          {recentLogs.length === 0 ? (
            <div style={{ padding: '24px 0', textAlign: 'center' }} className="text-secondary text-sm">
              {loading ? 'Querying blockchain ledger...' : 'No provenance blocks recorded yet.'}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {recentLogs.map((log) => (
                <div
                  key={log._id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-xs)'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className="font-mono text-xs font-bold text-primary">#{log.sequenceNumber}</span>
                    <span className={`badge ${log.status === 'SUCCESS' ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: '9px' }}>
                      {log.action}
                    </span>
                  </div>

                  <div style={{ textAlign: 'right' }}>
                    <div className="font-mono text-xs text-dim">
                      {log.entryHash ? `${log.entryHash.slice(0, 10)}...${log.entryHash.slice(-8)}` : 'N/A'}
                    </div>
                    <div className="text-xs text-muted" style={{ fontSize: '10px' }}>
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>

    </div>
  );
}
