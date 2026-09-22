'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '../../lib/authContext';
import { api, DocumentMeta, TraitorTracingReport } from '../../lib/api';
import { Search, ShieldAlert, Cpu, AlertTriangle, CheckCircle, FileText, ArrowRight, Zap, Award } from 'lucide-react';

export function ForensicsConsole() {
  const { token } = useAuth();
  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [selectedDocId, setSelectedDocId] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'trace' | 'simulate'>('trace');

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
            <span className="badge">TARDOS COLLUSION RESISTANCE</span>
          </div>
          <h1 className="text-xl font-bold">Traitor Tracing & Coalition Collusion Analysis</h1>
          <p className="text-secondary text-sm" style={{ marginTop: '2px' }}>
            Accuse colluders holding differing copies of an encrypted document using symmetric Tardos score weighting: <span className="font-mono text-primary">Z = 1.25√m</span>.
          </p>
        </div>

        {/* Mode Switcher Tabs */}
        <div style={{ display: 'flex', gap: '6px', background: 'var(--bg-secondary)', padding: '4px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-medium)' }}>
          <button
            onClick={() => setActiveTab('trace')}
            className={`btn btn-sm ${activeTab === 'trace' ? 'btn-primary' : 'btn-secondary'}`}
          >
            <Search size={12} />
            <span>LEAK TRACER</span>
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
          <span className="input-label" style={{ marginBottom: 0 }}>Target Document:</span>
          <select
            value={selectedDocId}
            onChange={(e) => {
              setSelectedDocId(e.target.value);
              setTraceResult(null);
              setSimResult(null);
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
            <span>Recipients: <strong className="text-primary">{selectedDoc.recipientKeys?.length || selectedDoc.recipientCount || 0}</strong></span>
            <span>Ciphertext Hash: <strong className="text-primary">{selectedDoc.fileHash.slice(0, 12)}...</strong></span>
          </div>
        )}
      </div>

      {/* Main Mode View */}
      {activeTab === 'trace' ? (
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
                  <div style={{ background: '#1c1212', border: '1px solid #7f1d1d', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#f87171' }}>
                      <ShieldAlert size={18} />
                      <span className="font-bold text-sm">TRAITOR(S) IDENTIFIED WITH PROVABLE CONFIDENCE</span>
                    </div>
                    <div className="text-xs text-secondary" style={{ marginTop: '6px' }}>
                      Identified <strong className="text-primary">{traceResult.report.colluderCount} recipient(s)</strong> whose Tardos correlation scores exceed the detection threshold Z = {traceResult.report.threshold}.
                    </div>
                  </div>
                ) : (
                  <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-medium)', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#34d399' }}>
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
                  <div key={acc.recipientId} className="card card-elevated" style={{ border: '1px solid #ffffff' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span className="badge badge-danger">ACCUSED TRAITOR</span>
                        <div className="font-bold text-base text-primary" style={{ marginTop: '4px' }}>
                          {acc.username}
                        </div>
                        <div className="font-mono text-xs text-muted">{acc.email}</div>
                      </div>

                      <div style={{ textAlign: 'right' }}>
                        <div className="text-2xl font-bold font-mono text-primary">{acc.confidencePercentage}%</div>
                        <div className="uppercase-track text-muted" style={{ fontSize: '9px' }}>Statistical Confidence</div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '12px', borderTop: '1px solid var(--border-subtle)', paddingTop: '8px', fontSize: '11px' }}>
                      <span className="text-muted">Accusation Score: <strong className="font-mono text-primary">{acc.score}</strong></span>
                      <span className="text-muted">Threshold Z: <strong className="font-mono text-primary">{acc.threshold}</strong></span>
                    </div>
                  </div>
                ))}

                {/* Ranked Candidate Score Bars */}
                <div>
                  <div className="uppercase-track text-muted" style={{ fontSize: '10px', marginBottom: '8px' }}>
                    Candidate Recipient Score Spectrum
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {traceResult.report.rankedCandidates.map((c) => {
                      const isAccused = c.score >= traceResult.report.threshold;
                      const maxScore = Math.max(traceResult.report.threshold * 1.5, 30);
                      const widthPercent = Math.min(100, Math.max(5, (c.score / maxScore) * 100));

                      return (
                        <div key={c.recipientId} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                            <span className={isAccused ? 'font-bold text-primary' : 'text-muted'}>
                              {c.username} {isAccused && '▲ ACCUSED'}
                            </span>
                            <span className="font-mono text-xs text-secondary">{c.score}</span>
                          </div>

                          <div style={{ width: '100%', height: '6px', background: 'var(--bg-input)', borderRadius: '3px', overflow: 'hidden' }}>
                            <div
                              style={{
                                width: `${widthPercent}%`,
                                height: '100%',
                                background: isAccused ? '#ffffff' : '#3f3f46',
                                transition: 'width 0.3s ease'
                              }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Server Digital Signature Proof */}
                <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                  <div className="text-xs font-semibold text-secondary" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Award size={13} color="#34d399" />
                    <span>Cryptographically Signed by Server Authority (RSA-SHA256)</span>
                  </div>
                  <div className="hex-box font-mono" style={{ fontSize: '9px', marginTop: '6px' }}>
                    SIG: {traceResult.serverSignature}
                  </div>
                </div>

              </div>
            ) : (
              <div className="text-muted text-xs" style={{ padding: '60px 0', textAlign: 'center' }}>
                Submit a suspect watermark codeword or file to execute traitor tracing.
              </div>
            )}
          </div>

        </div>
      ) : (
        /* Collusion Simulation View */
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) minmax(340px, 1fr)', gap: '24px' }}>
          
          {/* Left: Simulation Setup */}
          <div className="card">
            <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
              Configure Collusion Attack Coalition
            </div>

            {simError && (
              <div className="badge badge-danger" style={{ display: 'flex', width: '100%', padding: '8px 12px', marginBottom: '14px' }}>
                <AlertTriangle size={14} />
                <span>{simError}</span>
              </div>
            )}

            {/* Select Colluders */}
            <div className="input-group">
              <label className="input-label">Select Colluders (Minimum 2)</label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '180px', overflowY: 'auto', border: '1px solid var(--border-medium)', borderRadius: 'var(--radius-xs)', padding: '6px' }}>
                {selectedDoc?.recipientKeys?.map((rk: any) => {
                  const userObj = rk.recipientId;
                  const id = userObj._id || userObj.id;
                  const isChecked = selectedColluderIds.includes(id);

                  return (
                    <div
                      key={id}
                      onClick={() => toggleColluder(id)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '6px 10px',
                        cursor: 'pointer',
                        borderRadius: 'var(--radius-xs)',
                        background: isChecked ? 'rgba(255,255,255,0.08)' : 'transparent'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <input type="checkbox" checked={isChecked} onChange={() => {}} />
                        <span className="font-semibold text-xs text-primary">{userObj.username}</span>
                      </div>
                      <span className="badge text-xs" style={{ fontSize: '9px' }}>{userObj.role}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Strategy Selector */}
            <div className="input-group">
              <label className="input-label">Coalition Forgery Strategy</label>
              <select
                value={strategy}
                onChange={(e) => setStrategy(e.target.value as any)}
                className="input-select font-mono"
              >
                <option value="interleaving">Interleaving (Randomly mix bits among colluders)</option>
                <option value="majority">Majority Voting (Most frequent bit wins)</option>
                <option value="worst_case">Worst Case (Coin flip on disagreements)</option>
              </select>
            </div>

            <button
              onClick={handleSimulate}
              disabled={isSimulating || selectedColluderIds.length < 2}
              className="btn btn-primary"
              style={{ width: '100%', marginTop: '12px', padding: '12px' }}
            >
              <Zap size={14} />
              <span>{isSimulating ? 'FORGING WATERMARK & EXECUTING TRACE...' : 'SIMULATE COLLUSION ATTACK'}</span>
            </button>
          </div>

          {/* Right: Simulation Output */}
          <div className="card">
            <div className="uppercase-track text-muted" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
              Simulation & Unmasking Results
            </div>

            {simResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ background: '#1c1212', border: '1px solid #7f1d1d', borderRadius: 'var(--radius-xs)', padding: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#f87171' }}>
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
                Select 2 or more recipients and click Simulate to demonstrate how the coalition is unmasked.
              </div>
            )}
          </div>

        </div>
      )}

    </div>
  );
}
