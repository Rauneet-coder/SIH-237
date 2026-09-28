'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '../../lib/authContext';
import { api, DocumentMeta, TraitorTracingReport } from '../../lib/api';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  AlertTriangle,
  CheckCircle,
  FileText,
  ArrowRight,
  Zap,
  Award,
  Fingerprint,
  FileCheck,
  XCircle,
  Info,
  Clock,
  User as UserIcon,
  Database
} from 'lucide-react';

export function ForensicsConsole() {
  const { token } = useAuth();
  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [selectedDocId, setSelectedDocId] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'investigate' | 'trace' | 'simulate'>('investigate');

  // Leak Investigation State
  const [investigateFile, setInvestigateFile] = useState<File | null>(null);
  const [investigateWatermarkId, setInvestigateWatermarkId] = useState('');
  const [investigateCommitment, setInvestigateCommitment] = useState('');
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [investigationResult, setInvestigationResult] = useState<{
    extraction: any;
    verification: {
      overallStatus: string;
      ledgerSignatureValid: boolean;
      evidenceBindingValid: boolean;
      documentHashValid: boolean;
      commitmentValid: boolean;
      structuralLayoutValid: boolean;
      event?: any;
      recipient?: any;
      document?: any;
      signerPublicKey?: string;
      suspectFileHash?: string;
      recomputedCommitment?: string;
      limitations?: string[];
      notes?: string;
    };
  } | null>(null);
  const [investigationError, setInvestigationError] = useState<string | null>(null);

  // Trace State
  const [inputMode, setInputMode] = useState<'codeword' | 'file'>('codeword');
  const [watermarkCodeword, setWatermarkCodeword] = useState('');
  const [leakedFile, setLeakedFile] = useState<File | null>(null);
  const [isTracing, setIsTracing] = useState(false);
  const [traceResult, setTraceResult] = useState<{
    report: TraitorTracingReport;
    serverSignature: string;
    reportDigest: string;
  } | null>(null);
  const [traceError, setTraceError] = useState<string | null>(null);

  // Simulation State
  const [selectedColluderIds, setSelectedColluderIds] = useState<string[]>([]);
  const [strategy, setStrategy] = useState<'interleaving' | 'majority' | 'worst_case'>('interleaving');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simResult, setSimResult] = useState<{
    report: TraitorTracingReport;
    syntheticWatermark: string;
    colluderCount: number;
    collusionStrategy: string;
  } | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  useEffect(() => {
    async function loadDocs() {
      if (!token) return;
      try {
        const res = await api.listDocuments(token);
        setDocuments(res.documents || []);
        if (res.documents.length > 0 && !selectedDocId) {
          setSelectedDocId(res.documents[0]._id || res.documents[0].id!);
        }
      } catch (err) {
        console.error('Failed to load documents:', err);
      }
    }
    loadDocs();
  }, [token, selectedDocId]);

  const selectedDoc = documents.find((d) => (d._id || d.id) === selectedDocId);

  // Handle Full Leak Investigation (File extraction + commitment binding + ledger verification)
  const handleInvestigate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;

    if (!investigateFile && !investigateWatermarkId.trim()) {
      setInvestigationError('Please provide a suspect leaked document or enter an extracted watermark ID.');
      return;
    }

    setIsInvestigating(true);
    setInvestigationError(null);
    setInvestigationResult(null);

    try {
      const formData = new FormData();
      if (investigateFile) {
        formData.append('file', investigateFile);
      }
      if (selectedDocId) {
        formData.append('documentId', selectedDocId);
      }
      if (investigateWatermarkId.trim()) {
        formData.append('watermarkId', investigateWatermarkId.trim());
      }
      if (investigateCommitment.trim()) {
        formData.append('watermarkCommitment', investigateCommitment.trim());
      }

      const res = await api.investigateLeak(formData, token);
      setInvestigationResult(res);
    } catch (err: any) {
      setInvestigationError(err.message || 'Forensic investigation failed.');
    } finally {
      setIsInvestigating(false);
    }
  };

  const handleTrace = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !selectedDocId) return;

    setIsTracing(true);
    setTraceError(null);
    setTraceResult(null);

    try {
      let payload: { watermarkCodeword?: string; leakedContent?: string; isBase64?: boolean } = {};
      if (inputMode === 'codeword') {
        if (!watermarkCodeword.trim()) {
          throw new Error('Please enter a 256-bit suspect Tardos binary codeword.');
        }
        payload.watermarkCodeword = watermarkCodeword.trim();
      } else {
        if (!leakedFile) {
          throw new Error('Please select a suspect leaked document file.');
        }
        const text = await leakedFile.text();
        payload.leakedContent = text;
      }

      const res = await api.traceCollusion(selectedDocId, payload, token);
      setTraceResult({
        report: res.report,
        serverSignature: res.serverSignature,
        reportDigest: res.reportDigest
      });
    } catch (err: any) {
      setTraceError(err.message || 'Traitor tracing analysis failed.');
    } finally {
      setIsTracing(false);
    }
  };

  const handleSimulate = async () => {
    if (!token || !selectedDocId) return;
    if (selectedColluderIds.length < 2) {
      setSimError('Please select at least 2 recipients to form a colluding coalition.');
      return;
    }

    setIsSimulating(true);
    setSimError(null);
    setSimResult(null);

    try {
      const res = await api.simulateCollusion(selectedDocId, selectedColluderIds, strategy, token);
      setSimResult(res);
    } catch (err: any) {
      setSimError(err.message || 'Collusion simulation failed.');
    } finally {
      setIsSimulating(false);
    }
  };

  const toggleColluder = (id: string) => {
    setSelectedColluderIds((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Top Banner */}
      <div className="card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span className="badge badge-white">FORENSIC ATTRIBUTION ENGINE</span>
            <span className="badge">IMMUTABLE EVIDENCE VERIFICATION</span>
          </div>
          <h1 className="text-xl font-bold">Forensic Attribution & Traitor Tracing Suite</h1>
          <p className="text-secondary text-sm" style={{ marginTop: '2px' }}>
            Verify evidence attribution against tamper-evident ledger records and unmask leaking recipients with mathematical certainty.
          </p>
        </div>

        {/* Mode Switcher Tabs */}
        <div style={{ display: 'flex', gap: '6px', background: 'var(--bg-secondary)', padding: '4px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-medium)' }}>
          <button
            onClick={() => setActiveTab('investigate')}
            className={`btn btn-sm ${activeTab === 'investigate' ? 'btn-primary' : 'btn-secondary'}`}
          >
            <Fingerprint size={12} />
            <span>LEAK INVESTIGATION</span>
          </button>
          <button
            onClick={() => setActiveTab('trace')}
            className={`btn btn-sm ${activeTab === 'trace' ? 'btn-primary' : 'btn-secondary'}`}
          >
            <Search size={12} />
            <span>TARDOS TRACER</span>
          </button>
          <button
            onClick={() => setActiveTab('simulate')}
            className={`btn btn-sm ${activeTab === 'simulate' ? 'btn-primary' : 'btn-secondary'}`}
          >
            <Zap size={12} />
            <span>COLLUSION SIMULATOR</span>
          </button>
        </div>
      </div>

      {/* Target Document Selector */}
      <div className="card" style={{ padding: '14px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="input-label" style={{ marginBottom: 0 }}>Reference Document:</span>
          <select
            value={selectedDocId}
            onChange={(e) => {
              setSelectedDocId(e.target.value);
              setTraceResult(null);
              setSimResult(null);
              setInvestigationResult(null);
              setSelectedColluderIds([]);
            }}
            className="input-select font-mono"
            style={{ width: '320px', padding: '6px 10px' }}
          >
            {documents.map((d) => (
              <option key={d._id || d.id} value={d._id || d.id}>
                {d.title} ({d.fileName})
              </option>
            ))}
          </select>
        </div>

        {selectedDoc && (
          <div className="font-mono text-xs text-muted" style={{ display: 'flex', gap: '16px' }}>
            <span>Classification: <strong className="text-primary">{selectedDoc.classification || 'CONFIDENTIAL'}</strong></span>
            <span>Recipients: <strong className="text-primary">{selectedDoc.recipientKeys?.length || selectedDoc.recipientCount || 0}</strong></span>
            <span>Ciphertext Hash: <strong className="text-primary">{selectedDoc.fileHash.slice(0, 12)}...</strong></span>
          </div>
        )}
      </div>

      {/* TAB 1: EVIDENCE INVESTIGATION & BINDING VERIFICATION */}
      {activeTab === 'investigate' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1fr) minmax(400px, 1.3fr)', gap: '24px' }}>
          
          {/* Left: Investigation Intake Form */}
          <div className="card">
            <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
              Suspect Evidence Intake
            </div>

            {investigationError && (
              <div className="badge badge-danger" style={{ display: 'flex', width: '100%', padding: '8px 12px', marginBottom: '14px' }}>
                <AlertTriangle size={14} />
                <span>{investigationError}</span>
              </div>
            )}

            <form onSubmit={handleInvestigate} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="input-group">
                <label className="input-label">Suspect Leaked Document / Exfiltrated File</label>
                <input
                  type="file"
                  onChange={(e) => setInvestigateFile(e.target.files?.[0] || null)}
                  className="input-text"
                />
                <span className="text-xs text-muted" style={{ fontSize: '10px' }}>
                  Upload suspect PDF or document text recovered from leak site or breach channel.
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', margin: '4px 0' }}>
                <div style={{ flex: 1, height: '1px', background: 'var(--border-subtle)' }} />
                <span className="text-xs text-muted font-mono uppercase">OR SPECIFY KNOWN MARKERS</span>
                <div style={{ flex: 1, height: '1px', background: 'var(--border-subtle)' }} />
              </div>

              <div className="input-group">
                <label className="input-label">Watermark ID (Optional if file uploaded)</label>
                <input
                  type="text"
                  value={investigateWatermarkId}
                  onChange={(e) => setInvestigateWatermarkId(e.target.value)}
                  placeholder="e.g. WM-2026-..."
                  className="input-text font-mono"
                  style={{ fontSize: '12px' }}
                />
              </div>

              <div className="input-group">
                <label className="input-label">Watermark Commitment (Hex SHA-256)</label>
                <input
                  type="text"
                  value={investigateCommitment}
                  onChange={(e) => setInvestigateCommitment(e.target.value)}
                  placeholder="64-character hex commitment"
                  className="input-text font-mono"
                  style={{ fontSize: '12px' }}
                />
              </div>

              <button
                type="submit"
                disabled={isInvestigating}
                className="btn btn-primary"
                style={{ width: '100%', marginTop: '8px', padding: '12px' }}
              >
                <Fingerprint size={14} />
                <span>{isInvestigating ? 'ANALYZING & VERIFYING LINEAGE...' : 'RUN FORENSIC INVESTIGATION'}</span>
              </button>
            </form>

            <div style={{ marginTop: '20px', padding: '12px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                <Info size={13} />
                <span>Cryptographic Guardrails</span>
              </div>
              <p className="text-xs text-muted" style={{ marginTop: '4px', lineHeight: 1.5, fontSize: '11px' }}>
                Verifies both ledger authority signature AND recomputes watermark commitments from authenticated session context. Prevents marker-copying fraud by verifying structural layout integrity.
              </p>
            </div>
          </div>

          {/* Right: Forensic Verification & Attribution Report */}
          <div className="card">
            <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
              Forensic Attribution & Cryptographic Verification Report
            </div>

            {investigationResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                
                {/* Status Banner */}
                {investigationResult.verification.overallStatus === 'ATTRIBUTED' ? (
                  <div style={{ background: '#f7eae6', border: '1px solid #dfbcb2', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#aa493c' }}>
                      <ShieldAlert size={18} />
                      <span className="font-bold text-sm">EVIDENCE CONCLUSIVELY ATTRIBUTED TO RECIPIENT</span>
                    </div>
                    <div className="text-xs text-secondary" style={{ marginTop: '6px' }}>
                      Both ledger authority signature and session watermark commitments verified. Submitted evidence is cryptographically bound to recipient <strong className="text-primary">{investigationResult.verification.recipient?.username}</strong>.
                    </div>
                  </div>
                ) : investigationResult.verification.overallStatus === 'FRAUD_DETECTED' ? (
                  <div style={{ background: '#fdf0ed', border: '2px solid #c93b2b', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#c93b2b' }}>
                      <AlertTriangle size={18} />
                      <span className="font-bold text-sm">MARKER FRAUD DETECTED: STRUCTURAL MISMATCH</span>
                    </div>
                    <div className="text-xs text-secondary" style={{ marginTop: '6px' }}>
                      The extracted watermark was detected, but the document structural layout does not match the original document. The marker was fraudulently copied or pasted into unrelated content!
                    </div>
                  </div>
                ) : investigationResult.verification.overallStatus === 'MISMATCH' ? (
                  <div style={{ background: '#fff5eb', border: '1px solid #f3d1b0', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#b45309' }}>
                      <AlertTriangle size={18} />
                      <span className="font-bold text-sm">VERIFICATION MISMATCH</span>
                    </div>
                    <div className="text-xs text-secondary" style={{ marginTop: '6px' }}>
                      The extracted commitment or signature does not match the provenance ledger record.
                    </div>
                  </div>
                ) : (
                  <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-medium)', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)' }}>
                      <Info size={18} />
                      <span className="font-bold text-sm">INCONCLUSIVE EVIDENCE</span>
                    </div>
                    <div className="text-xs text-muted" style={{ marginTop: '4px' }}>
                      Insufficient evidence or missing source document. Attribution cannot be established with mathematical certainty.
                    </div>
                  </div>
                )}

                {/* Dual-Column Integrity Matrix */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  
                  {/* Ledger Record Integrity */}
                  <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                      <Database size={13} className="text-primary" />
                      <span className="font-semibold text-xs uppercase-track">Ledger Signature</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      {investigationResult.verification.ledgerSignatureValid ? (
                        <>
                          <CheckCircle size={14} style={{ color: '#2e7d32' }} />
                          <span className="font-mono text-xs font-bold" style={{ color: '#2e7d32' }}>VERIFIED (RSA-SHA256)</span>
                        </>
                      ) : (
                        <>
                          <XCircle size={14} style={{ color: '#c93b2b' }} />
                          <span className="font-mono text-xs font-bold" style={{ color: '#c93b2b' }}>INVALID / TAMPERED</span>
                        </>
                      )}
                    </div>
                    <div className="font-mono text-xs text-muted" style={{ marginTop: '6px', fontSize: '10px' }}>
                      Key ID: {investigationResult.verification.event?.authorityKeyId || 'DEFAULT-KEY-001'}
                    </div>
                  </div>

                  {/* Evidence Content Binding */}
                  <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                      <FileCheck size={13} className="text-primary" />
                      <span className="font-semibold text-xs uppercase-track">Evidence Binding</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      {investigationResult.verification.evidenceBindingValid ? (
                        <>
                          <CheckCircle size={14} style={{ color: '#2e7d32' }} />
                          <span className="font-mono text-xs font-bold" style={{ color: '#2e7d32' }}>BOUND TO SESSION</span>
                        </>
                      ) : (
                        <>
                          <XCircle size={14} style={{ color: '#c93b2b' }} />
                          <span className="font-mono text-xs font-bold" style={{ color: '#c93b2b' }}>BINDING FAILED</span>
                        </>
                      )}
                    </div>
                    <div className="font-mono text-xs text-muted" style={{ marginTop: '6px', fontSize: '10px' }}>
                      Commitment: {investigationResult.verification.commitmentValid ? 'MATCHED' : 'MISMATCH'}
                    </div>
                  </div>

                </div>

                {/* Attributed Recipient Card (if found) */}
                {investigationResult.verification.recipient && (
                  <div className="card card-elevated" style={{ border: '1px solid var(--text-primary)', padding: '14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="badge badge-danger">ATTRIBUTED LEAK OFFICER</span>
                      <span className="font-mono text-xs text-muted">ID: {investigationResult.verification.recipient._id}</span>
                    </div>
                    
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px', marginTop: '12px' }}>
                      <div>
                        <span className="text-xs text-muted uppercase-track" style={{ fontSize: '10px' }}>Officer Username</span>
                        <div className="font-bold text-sm text-primary">{investigationResult.verification.recipient.username}</div>
                      </div>
                      <div>
                        <span className="text-xs text-muted uppercase-track" style={{ fontSize: '10px' }}>Rank / Role</span>
                        <div className="font-bold text-sm text-primary">{investigationResult.verification.recipient.role}</div>
                      </div>
                      <div>
                        <span className="text-xs text-muted uppercase-track" style={{ fontSize: '10px' }}>Clearance</span>
                        <div className="font-bold text-sm text-primary">{investigationResult.verification.recipient.clearance || 'RESTRICTED'}</div>
                      </div>
                      <div>
                        <span className="text-xs text-muted uppercase-track" style={{ fontSize: '10px' }}>Decryption Session</span>
                        <div className="font-mono text-xs text-primary">{investigationResult.verification.event?.sessionId?.slice(0, 14)}...</div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)', fontSize: '11px' }}>
                      <Clock size={12} className="text-muted" />
                      <span className="text-muted">Decryption Event Recorded:</span>
                      <span className="font-mono text-primary font-semibold">{investigationResult.verification.event?.timestamp ? new Date(investigationResult.verification.event.timestamp).toLocaleString() : 'N/A'}</span>
                    </div>
                  </div>
                )}

                {/* Evidence Hashes & Lineage */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <span className="input-label" style={{ marginBottom: 0 }}>Server-Derived Evidence Lineage:</span>
                  <div className="hex-box font-mono" style={{ fontSize: '10px' }}>
                    <div>Suspect File SHA-256: {investigationResult.verification.suspectFileHash || 'N/A'}</div>
                    {investigationResult.verification.recomputedCommitment && (
                      <div style={{ marginTop: '4px' }}>Recomputed Commitment: {investigationResult.verification.recomputedCommitment}</div>
                    )}
                    {investigationResult.verification.event?.entryHash && (
                      <div style={{ marginTop: '4px' }}>Ledger Entry Hash: {investigationResult.verification.event.entryHash}</div>
                    )}
                  </div>
                </div>

                {/* Engineering Limitations Disclosure */}
                {investigationResult.verification.limitations && investigationResult.verification.limitations.length > 0 && (
                  <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-subtle)' }}>
                    <div className="uppercase-track text-muted" style={{ fontSize: '10px', marginBottom: '4px' }}>
                      Engineering Limitations & Standards
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {investigationResult.verification.limitations.map((lim, idx) => (
                        <li key={idx} style={{ marginTop: '2px' }}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                )}

              </div>
            ) : (
              <div className="text-muted text-xs" style={{ padding: '60px 0', textAlign: 'center' }}>
                Upload a suspect document or provide extracted watermark identifiers to run verification against the immutable provenance ledger.
              </div>
            )}
          </div>

        </div>
      )}

      {/* TAB 2: TARDOS TRAITOR TRACER */}
      {activeTab === 'trace' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) minmax(340px, 1fr)', gap: '24px' }}>
          
          {/* Left: Input Form */}
          <div className="card">
            <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
              Suspect Watermark & Leaked Data Input
            </div>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
              <button
                type="button"
                onClick={() => setInputMode('codeword')}
                className={`btn btn-sm ${inputMode === 'codeword' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ flex: 1 }}
              >
                Binary Codeword
              </button>
              <button
                type="button"
                onClick={() => setInputMode('file')}
                className={`btn btn-sm ${inputMode === 'file' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ flex: 1 }}
              >
                Upload Leaked File
              </button>
            </div>

            {traceError && (
              <div className="badge badge-danger" style={{ display: 'flex', width: '100%', padding: '8px 12px', marginBottom: '14px' }}>
                <AlertTriangle size={14} />
                <span>{traceError}</span>
              </div>
            )}

            <form onSubmit={handleTrace}>
              {inputMode === 'codeword' ? (
                <div className="input-group">
                  <label className="input-label">Extracted Tardos Binary Fingerprint (256 Bits)</label>
                  <textarea
                    rows={4}
                    value={watermarkCodeword}
                    onChange={(e) => setWatermarkCodeword(e.target.value)}
                    placeholder="e.g. 1011001010111001010110100101..."
                    className="input-textarea input-mono"
                    style={{ fontSize: '11px', letterSpacing: '0.05em' }}
                    required
                  />
                  <span className="text-xs text-muted" style={{ fontSize: '10px' }}>
                    Tip: If testing, run a simulation first or enter an extracted codeword.
                  </span>
                </div>
              ) : (
                <div className="input-group">
                  <label className="input-label">Suspect Leaked Document File</label>
                  <input
                    type="file"
                    onChange={(e) => setLeakedFile(e.target.files?.[0] || null)}
                    className="input-text"
                    required
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={isTracing || !selectedDocId}
                className="btn btn-primary"
                style={{ width: '100%', marginTop: '12px', padding: '12px' }}
              >
                <Search size={14} />
                <span>{isTracing ? 'CALCULATING ACCUSATION SCORES...' : 'RUN TRAITOR TRACING ALGORITHM'}</span>
              </button>
            </form>
          </div>

          {/* Right: Accusation Findings & Candidate Ranking */}
          <div className="card">
            <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
              Traitor Tracing Accusation Report
            </div>

            {traceResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                
                {/* Collusion Detected Banner */}
                {traceResult.report.collusionDetected ? (
                  <div style={{ background: '#f7eae6', border: '1px solid #dfbcb2', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#aa493c' }}>
                      <ShieldAlert size={18} />
                      <span className="font-bold text-sm">TRAITOR(S) IDENTIFIED WITH PROVABLE CONFIDENCE</span>
                    </div>
                    <div className="text-xs text-secondary" style={{ marginTop: '6px' }}>
                      Identified <strong className="text-primary">{traceResult.report.colluderCount} recipient(s)</strong> whose Tardos correlation scores exceed the detection threshold Z = {traceResult.report.threshold}.
                    </div>
                  </div>
                ) : (
                  <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-medium)', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#52764a' }}>
                      <CheckCircle size={18} />
                      <span className="font-bold text-sm">NO COLLUSION DETECTED</span>
                    </div>
                    <div className="text-xs text-muted" style={{ marginTop: '4px' }}>
                      All recipient correlation scores remain within innocent bounds (below Z = {traceResult.report.threshold}).
                    </div>
                  </div>
                )}

                {/* Accused Recipients Cards */}
                {traceResult.report.accusedRecipients.map((acc) => (
                  <div key={acc.recipientId} className="card card-elevated" style={{ border: '1px solid var(--text-primary)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span className="badge badge-danger">ACCUSED TRAITOR</span>
                        <div className="font-bold text-base text-primary" style={{ marginTop: '4px' }}>
                          {acc.username}
                        </div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <span className="text-xs text-muted uppercase-track" style={{ fontSize: '10px' }}>Accusation Score</span>
                        <div className="font-mono text-lg font-bold text-primary">{acc.score}</div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
                      <span className="text-xs text-muted">Exceeds Threshold (Z &gt; {traceResult.report.threshold}):</span>
                      <span className="badge badge-white font-mono">
                        {acc.confidencePercentage}% CONFIDENCE
                      </span>
                    </div>
                  </div>
                ))}

                {/* Cryptographic Attestation Block */}
                <div>
                  <span className="input-label">Server Forensic Authority Digital Signature (RSA-SHA256):</span>
                  <div className="hex-box font-mono" style={{ fontSize: '10px', marginTop: '4px' }}>
                    {traceResult.serverSignature}
                  </div>
                  <div className="text-xs text-muted" style={{ marginTop: '4px', fontSize: '10px' }}>
                    Report Digest: <span className="font-mono text-primary">{traceResult.reportDigest}</span>
                  </div>
                </div>

              </div>
            ) : (
              <div className="text-muted text-xs" style={{ padding: '60px 0', textAlign: 'center' }}>
                Enter suspect codeword or upload a leaked file to calculate correlation scores.
              </div>
            )}
          </div>

        </div>
      )}

      {/* TAB 3: COLLUSION SIMULATOR */}
      {activeTab === 'simulate' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) minmax(340px, 1fr)', gap: '24px' }}>
          
          {/* Left: Simulation Setup */}
          <div className="card">
            <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
              Collusion Simulation Parameters
            </div>

            {simError && (
              <div className="badge badge-danger" style={{ display: 'flex', width: '100%', padding: '8px 12px', marginBottom: '14px' }}>
                <AlertTriangle size={14} />
                <span>{simError}</span>
              </div>
            )}

            {/* Recipient Coalition Selection */}
            <div className="input-group">
              <label className="input-label">Select Colluding Coalition (Minimum 2 Recipients):</label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '180px', overflowY: 'auto' }}>
                {(selectedDoc?.recipientKeys || []).map((rk: any) => {
                  const rId = rk.recipientId?._id || rk.recipientId;
                  const rUsername = rk.recipientId?.username || rId;
                  const isSelected = selectedColluderIds.includes(rId);

                  return (
                    <label
                      key={rId}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                        padding: '8px 10px',
                        background: isSelected ? 'var(--bg-secondary)' : 'transparent',
                        border: isSelected ? '1px solid var(--border-medium)' : '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-xs)',
                        cursor: 'pointer'
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleColluder(rId)}
                      />
                      <span className="font-mono text-xs text-primary">{rUsername}</span>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Collusion Attack Strategy */}
            <div className="input-group">
              <label className="input-label">Adversarial Strategy:</label>
              <select
                value={strategy}
                onChange={(e: any) => setStrategy(e.target.value)}
                className="input-select font-mono"
              >
                <option value="interleaving">Interleaving Attack (Random mix of recipient bits)</option>
                <option value="majority">Majority Voting Attack (Most frequent bit at each position)</option>
                <option value="worst_case">Worst-Case Adversarial Erasure (Flip detectable bits)</option>
              </select>
            </div>

            <button
              onClick={handleSimulate}
              disabled={isSimulating || selectedColluderIds.length < 2}
              className="btn btn-primary"
              style={{ width: '100%', marginTop: '8px', padding: '12px' }}
            >
              <Zap size={14} />
              <span>{isSimulating ? 'SIMULATING COLLUSION ATTACK...' : 'GENERATE SYNTHETIC ATTACK & TEST TRACER'}</span>
            </button>
          </div>

          {/* Right: Simulation Output */}
          <div className="card">
            <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
              Simulation & Unmasking Results
            </div>

            {simResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ background: '#f7eae6', border: '1px solid #dfbcb2', borderRadius: 'var(--radius-xs)', padding: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#aa493c' }}>
                    <ShieldAlert size={16} />
                    <span className="font-bold text-sm">COALITION SUCCESSFULLY UNMASKED</span>
                  </div>
                  <div className="text-xs text-secondary" style={{ marginTop: '4px' }}>
                    Despite the {simResult.colluderCount} colluders combining their copies using the <span className="font-mono text-primary font-bold">{simResult.collusionStrategy}</span> strategy, the Tardos accusation algorithm successfully identified every member of the coalition!
                  </div>
                </div>

                {/* Forged Synthetic Watermark */}
                <div>
                  <span className="input-label">Forged Synthetic Watermark (First 64 Bits):</span>
                  <div className="hex-box font-mono" style={{ fontSize: '10px', marginTop: '4px' }}>
                    {simResult.syntheticWatermark.slice(0, 64)}...
                  </div>
                </div>

                {/* Accused Colluders in Simulation */}
                <div>
                  <div className="uppercase-track text-muted" style={{ fontSize: '10px', marginBottom: '8px' }}>
                    Unmasked Colluders (Score &gt; Threshold {simResult.report.threshold})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {simResult.report.accusedRecipients.map((acc) => (
                      <div
                        key={acc.recipientId}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '10px 12px',
                          background: 'var(--bg-secondary)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-xs)'
                        }}
                      >
                        <div>
                          <div className="font-semibold text-xs text-primary">{acc.username}</div>
                          <div className="text-xs text-muted" style={{ fontSize: '10px' }}>Score: {acc.score}</div>
                        </div>
                        <span className="badge badge-white font-mono" style={{ fontSize: '10px' }}>
                          {acc.confidencePercentage}% CONFIDENCE
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

              </div>
            ) : (
              <div className="text-muted text-xs" style={{ padding: '60px 0', textAlign: 'center' }}>
                Select 2 or more recipients and execute adversarial collusion attack analysis to unmask colluders.
              </div>
            )}
          </div>

        </div>
      )}

    </div>
  );
}
