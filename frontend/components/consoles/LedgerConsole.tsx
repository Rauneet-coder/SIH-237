'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '../../lib/authContext';
import { api, ProvenanceLogEntry, VerificationReport } from '../../lib/api';
import { Database, ShieldCheck, AlertTriangle, RefreshCw, CheckCircle, Award, Filter, ExternalLink } from 'lucide-react';

export function LedgerConsole() {
  const { token } = useAuth();
  const [logs, setLogs] = useState<ProvenanceLogEntry[]>([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [actionFilter, setActionFilter] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);

  // Verification Audit State
  const [isVerifying, setIsVerifying] = useState(false);
  const [auditReport, setAuditReport] = useState<VerificationReport | null>(null);
  const [serverPublicKey, setServerPublicKey] = useState<string | null>(null);
  const [showAuditModal, setShowAuditModal] = useState(false);

  const loadLogs = async () => {
    if (!token) return;
    setIsLoading(true);
    try {
      const params: Record<string, string> = { limit: '100' };
      if (actionFilter) params.action = actionFilter;
      const res = await api.listLogs(params, token);
      setLogs(res.logs || []);
      setTotalLogs(res.total || 0);
    } catch (err) {
      console.error('Failed to load ledger logs:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [token, actionFilter]);

  const handleVerifyChain = async () => {
    setIsVerifying(true);
    try {
      const res = await api.verifyChain();
      setAuditReport(res.report);
      setServerPublicKey(res.serverPublicKey);
      setShowAuditModal(true);
    } catch (err: any) {
      console.error('Verification failed:', err);
      alert(`Ledger verification failed: ${err.message}`);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Top Banner & Audit Action */}
      <div className="card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span className="badge badge-white">IMMUTABLE PROVENANCE LEDGER</span>
            <span className="badge">RSA-SHA256 SIGNED HASH-CHAIN</span>
          </div>
          <h1 className="text-xl font-bold">Cryptographic Decryption & Access Audit Trail</h1>
          <p className="text-secondary text-sm" style={{ marginTop: '2px' }}>
            Every upload and decryption attempt is sequentially hash-chained and digitally signed by the server authority.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button onClick={loadLogs} className="btn btn-secondary btn-sm" title="Refresh Logs">
            <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
            <span>REFRESH</span>
          </button>

          <button
            onClick={handleVerifyChain}
            disabled={isVerifying}
            className="btn btn-primary"
            style={{ padding: '9px 16px' }}
          >
            <ShieldCheck size={14} />
            <span>{isVerifying ? 'VERIFYING LEDGER...' : 'VERIFY ENTIRE HASH-CHAIN'}</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter size={13} className="text-secondary" />
          <span className="uppercase-track text-secondary text-xs">Filter by Action:</span>
          {['', 'ENCRYPT_UPLOAD', 'DECRYPT_SUCCESS', 'DECRYPT_FAILURE'].map((act) => (
            <button
              key={act}
              onClick={() => setActionFilter(act)}
              className={`btn btn-sm ${actionFilter === act ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '10px', padding: '4px 8px' }}
            >
              {act === '' ? 'ALL' : act}
            </button>
          ))}
        </div>

        <span className="font-mono text-xs text-muted">
          Showing {logs.length} of {totalLogs} ledger blocks
        </span>
      </div>

      {/* Tabular Block Explorer */}
      <div className="table-wrapper">
        <table className="tactical-table font-mono">
          <thead>
            <tr>
              <th style={{ width: '60px' }}>SEQ</th>
              <th>TIMESTAMP</th>
              <th>ACTION</th>
              <th>STATUS</th>
              <th>DOCUMENT</th>
              <th>ACTOR / RECIPIENT</th>
              <th>ENTRY HASH (SHA-256)</th>
              <th>PREV HASH</th>
              <th>SIGNATURE</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '30px' }} className="text-muted">
                  Querying immutable ledger blocks...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '30px' }} className="text-muted">
                  No provenance records recorded for this filter.
                </td>
              </tr>
            ) : (
              logs.map((log) => {
                const isGenesis = log.sequenceNumber === 1;
                return (
                  <tr key={log._id}>
                    <td className="font-bold text-primary">#{log.sequenceNumber}</td>
                    <td className="text-muted" style={{ fontSize: '11px' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="badge text-xs" style={{ fontSize: '9px', padding: '2px 5px' }}>
                        {log.action}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${log.status === 'SUCCESS' ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: '9px' }}>
                        {log.status}
                      </span>
                    </td>
                    <td className="text-primary" style={{ fontSize: '11px' }}>
                      {log.docId?.title || log.docId?.fileName || 'System Document'}
                    </td>
                    <td className="text-secondary" style={{ fontSize: '11px' }}>
                      {log.recipientId?.username || 'Authority'}
                    </td>
                    <td className="text-dim" style={{ fontSize: '10px' }} title={log.entryHash}>
                      {log.entryHash ? `${log.entryHash.slice(0, 10)}...${log.entryHash.slice(-8)}` : 'N/A'}
                    </td>
                    <td className="text-dim" style={{ fontSize: '10px' }} title={log.prevHash}>
                      {isGenesis ? (
                        <span className="text-secondary font-bold">GENESIS (0x00...00)</span>
                      ) : (
                        `${log.prevHash.slice(0, 10)}...`
                      )}
                    </td>
                    <td className="text-dim" style={{ fontSize: '10px' }} title={log.signature}>
                      {log.signature ? `${log.signature.slice(0, 8)}...` : 'N/A'}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* 1-Click Cryptographic Audit Modal */}
      {showAuditModal && auditReport && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            padding: '20px'
          }}
        >
          <div className="card card-elevated" style={{ width: '100%', maxWidth: '640px', border: '1px solid #ffffff' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldCheck size={20} color="#34d399" />
                <span className="font-bold text-base text-primary">FULL CHAIN CRYPTOGRAPHIC AUDIT REPORT</span>
              </div>
              <button onClick={() => setShowAuditModal(false)} className="btn btn-secondary btn-sm">
                CLOSE
              </button>
            </div>

            {/* Audit Status Banner */}
            <div style={{ margin: '16px 0', padding: '14px', borderRadius: 'var(--radius-xs)', background: auditReport.valid ? '#0d2818' : '#2b1212', border: `1px solid ${auditReport.valid ? '#065f46' : '#7f1d1d'}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: auditReport.valid ? '#34d399' : '#f87171' }}>
                {auditReport.valid ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
                <span className="font-bold text-sm">
                  {auditReport.valid ? 'PROVENANCE CHAIN INTEGRITY 100% VERIFIED' : 'TAMPER DETECTED IN LEDGER CHAIN'}
                </span>
              </div>
              <div className="text-xs text-secondary" style={{ marginTop: '4px' }}>
                {auditReport.valid
                  ? `All ${auditReport.totalBlocks} blocks sequentially verified from genesis to head with valid RSA-SHA256 signatures.`
                  : `Tampered block sequences: ${auditReport.tamperedSequences.join(', ')}`}
              </div>
            </div>

            {/* Audit Checks Checklist */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-xs)' }}>
                <span className="text-secondary">Total Blocks Evaluated:</span>
                <span className="font-mono font-bold text-primary">{auditReport.totalBlocks} Blocks</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-xs)' }}>
                <span className="text-secondary">Genesis Block Root (64 Zeroes):</span>
                <span className={`badge ${auditReport.genesisValid ? 'badge-success' : 'badge-danger'}`}>
                  {auditReport.genesisValid ? 'VERIFIED' : 'INVALID'}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-xs)' }}>
                <span className="text-secondary">Sequential Hash Linkage (H_k = SHA256(prevHash || docId || ...)):</span>
                <span className={`badge ${auditReport.chainIntegrityValid ? 'badge-success' : 'badge-danger'}`}>
                  {auditReport.chainIntegrityValid ? 'UNBROKEN' : 'BROKEN'}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-xs)' }}>
                <span className="text-secondary">Server RSA Authority Signatures:</span>
                <span className={`badge ${auditReport.allSignaturesValid ? 'badge-success' : 'badge-danger'}`}>
                  {auditReport.allSignaturesValid ? 'ALL SIGNATURES VALID' : 'SIGNATURE FAILURE'}
                </span>
              </div>
            </div>

            {/* Server Public Key */}
            {serverPublicKey && (
              <div style={{ marginTop: '16px', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
                <span className="input-label">Server Authority Public Key:</span>
                <div className="hex-box font-mono" style={{ fontSize: '9px', marginTop: '4px', maxHeight: '70px' }}>
                  {serverPublicKey}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
