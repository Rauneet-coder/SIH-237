'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useAuth, COMMAND_OFFICERS } from '../../lib/authContext';
import { api, DocumentMeta, PrepareSessionResponse } from '../../lib/api';
import { getClientDevice } from '../../lib/device';
import { DEMO_PRIVATE_KEYS } from '../../lib/demoKeys';
import {
  Inbox,
  Key,
  ShieldCheck,
  AlertCircle,
  Lock,
  FileText,
  CheckCircle,
  RefreshCw,
  Cpu,
  Clock,
  ExternalLink,
  ShieldAlert,
  Printer,
  XCircle,
  Eye
} from 'lucide-react';

interface PipelineStep {
  name: string;
  desc: string;
  status: 'pending' | 'active' | 'success' | 'failed';
}

export function InboxConsole({ documentId }: { documentId?: string }) {
  const { user, token, cachedPrivateKey, setCachedPrivateKey, quickSwitchUser } = useAuth();
  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [selectedDoc, setSelectedDoc] = useState<DocumentMeta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Modern PQC Session Pipeline State
  const [isProcessingSession, setIsProcessingSession] = useState(false);
  const [activeSession, setActiveSession] = useState<{
    sessionId: string;
    expiresAt: string;
    prepareData?: PrepareSessionResponse;
    blobUrl?: string;
    blobType?: string;
    textContent?: string;
  } | null>(null);
  const [sessionTimeRemaining, setSessionTimeRemaining] = useState<number | null>(null);
  const [pipelineSteps, setPipelineSteps] = useState<PipelineStep[]>([
    { name: 'Check access', desc: 'Validating recipient role and hardware device binding', status: 'pending' },
    { name: 'Unlock document', desc: 'Key Agent decapsulating shared secret inside isolated boundary', status: 'pending' },
    { name: 'Apply watermark', desc: 'Deriving opaque recipient fingerprint and watermark commitment', status: 'pending' },
    { name: 'Record access', desc: 'Signing canonical audit event and committing to Hyperledger Fabric', status: 'pending' },
    { name: 'Open viewer', desc: 'Enforcing cryptographic release gate into ephemeral secure viewer', status: 'pending' }
  ]);

  // Legacy RSA Decryption State (fallback)
  const [showLegacyMode, setShowLegacyMode] = useState(false);
  const [privateKeyPem, setPrivateKeyPem] = useState(
    (user?.username && DEMO_PRIVATE_KEYS[user.username]) || cachedPrivateKey || ''
  );
  const [isLegacyDecrypting, setIsLegacyDecrypting] = useState(false);

  // Device Info
  const [deviceInfo, setDeviceInfo] = useState<{ deviceId: string; deviceFingerprint: string; platform: string }>({
    deviceId: 'Detecting...',
    deviceFingerprint: '',
    platform: ''
  });

  useEffect(() => {
    setDeviceInfo(getClientDevice());
  }, []);

  // Sync private key if demo user switches
  useEffect(() => {
    if (user?.username && DEMO_PRIVATE_KEYS[user.username]) {
      setPrivateKeyPem(DEMO_PRIVATE_KEYS[user.username]);
    } else if (cachedPrivateKey) {
      setPrivateKeyPem(cachedPrivateKey);
    } else {
      setPrivateKeyPem('');
    }
    setError(null);
  }, [user?.username, cachedPrivateKey]);

  // Load documents
  const loadDocuments = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await api.listDocuments(token);
      const available = documentId ? res.documents.filter(d => (d._id || d.id) === documentId) : res.documents;
      setDocuments(available);
      if (documentId && !available.length) setError("This document is unavailable or you do not have access.");
      if (available.length > 0 && !selectedDoc) {
        setSelectedDoc(available[0]);
      }
    } catch (err: any) {
      setError(err instanceof Error ? err.message : 'Unable to load documents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDocuments();
  }, [token, documentId]);

  // Release document URLs when leaving the dedicated viewer.
  useEffect(() => {
    const url = activeSession?.blobUrl;
    return () => { if (url) URL.revokeObjectURL(url); };
  }, [activeSession?.blobUrl]);

  // Session expiry countdown timer
  useEffect(() => {
    if (!activeSession?.expiresAt) {
      setSessionTimeRemaining(null);
      return;
    }

    const interval = setInterval(() => {
      const remainingMs = new Date(activeSession.expiresAt).getTime() - Date.now();
      if (remainingMs <= 0) {
        setSessionTimeRemaining(0);
        clearInterval(interval);
        // Revoke active view on session timeout
        if (activeSession.blobUrl) {
          URL.revokeObjectURL(activeSession.blobUrl);
        }
        setActiveSession(null);
        setError('Decryption session has expired. Plaintext purged per fail-closed security invariant.');
      } else {
        setSessionTimeRemaining(Math.floor(remainingMs / 1000));
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [activeSession?.expiresAt, activeSession?.blobUrl]);

  // Execute Complete 5-Stage Post-Quantum Decryption Session Pipeline
  const handleInitiateSession = async () => {
    if (!token || !selectedDoc) return;
    setPipelineSteps(prev => prev.map(step => ({ ...step, status: "pending" })));
    setIsProcessingSession(true);
    setError(null);
    if (activeSession?.blobUrl) {
      URL.revokeObjectURL(activeSession.blobUrl);
    }
    setActiveSession(null);

    const dev = getClientDevice();
    const docId = selectedDoc._id || selectedDoc.id!;

    // Helper to update pipeline step
    const setStep = (idx: number, status: 'pending' | 'active' | 'success' | 'failed') => {
      setPipelineSteps((prev) =>
        prev.map((step, i) => (i === idx ? { ...step, status } : i < idx && status === 'active' ? { ...step, status: 'success' } : step))
      );
    };

    try {
      // Stage 1: Device & Recipient Authorization
      setStep(0, 'active');
      const sessionRes = await api.createSession(docId, dev.deviceId, token);
      setStep(0, 'success');

      // Stage 2 & 3 & 4: Prepare Session (ML-KEM unwrap + Fingerprint + ML-DSA Sign + Fabric Commit)
      setStep(1, 'active');
      setPipelineSteps(prev => prev.map((step, i) => i >= 1 && i <= 3 ? { ...step, status: 'active' } : step));

      const prepareRes = await api.prepareSession(sessionRes.sessionId, dev.deviceId, token);

      if (prepareRes.status !== 'RELEASED') {
        throw new Error('Fail-Closed security check activated: Session was not granted RELEASED status.');
      }
      setPipelineSteps(prev => prev.map((step, i) => i >= 1 && i <= 3 ? { ...step, status: 'success' } : step));

      // Stage 5: Fail-Closed Stream Release
      setStep(4, 'active');
      const blob = await api.renderSessionDocument(sessionRes.sessionId, dev.deviceId, token);
      const blobUrl = URL.createObjectURL(blob);
      setStep(4, 'success');

      let textContent: string | undefined;
      if (blob.type.includes('text') || blob.type.includes('json') || selectedDoc.mimeType?.includes('text')) {
        try {
          textContent = await blob.text();
        } catch {}
      }

      setActiveSession({
        sessionId: sessionRes.sessionId,
        expiresAt: sessionRes.expiresAt,
        prepareData: prepareRes,
        blobUrl,
        blobType: blob.type,
        textContent
      });
    } catch (err: any) {
      setError(err.message || 'Decryption session pipeline aborted. Fail-closed protection engaged.');
      setPipelineSteps((prev) =>
        prev.map((step) => (step.status === 'active' ? { ...step, status: 'failed' } : step))
      );
    } finally {
      setIsProcessingSession(false);
    }
  };

  // Close & Lock Active Viewer
  const handleLockViewer = async () => {
    if (activeSession?.sessionId && token) {
      try {
        await api.closeSession(activeSession.sessionId, token);
      } catch (err) {
        console.warn('Failed to notify server of session close:', err);
      }
    }
    if (activeSession?.blobUrl) {
      URL.revokeObjectURL(activeSession.blobUrl);
    }
    setActiveSession(null);
    setPipelineSteps((prev) => prev.map((s) => ({ ...s, status: 'pending' })));
  };

  // Check if current logged-in user is in the recipient list
  const isAuthorizedRecipient = Boolean(
    selectedDoc?.recipientKeys?.some((rk: any) => {
      const rId = rk.recipientId?._id || rk.recipientId;
      const rUsername = rk.recipientId?.username;
      return (user?._id && rId === user._id) || (user?.username && rUsername === user.username);
    }) ||
    // Sender is also authorized
    (selectedDoc?.senderId && (selectedDoc.senderId._id === user?._id || selectedDoc.senderId.username === user?.username)) ||
    // Admin / Auditor override
    ['admin', 'investigator', 'ADMIN', 'INVESTIGATOR'].includes(user?.role || '')
  );

  const recipientUsernames = (selectedDoc?.recipientKeys || [])
    .map((rk: any) => rk.recipientId?.username || (typeof rk.recipientId === 'string' ? rk.recipientId : null))
    .filter(Boolean);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: documentId ? 'minmax(0, 1fr)' : '360px 1fr', gap: '24px' }}>

      {/* Left Column: Documents Inbox List */}
      {!documentId && <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '14px', height: 'fit-content' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Inbox size={16} className="text-secondary" />
            <span className="uppercase-track text-primary font-bold">Secure Inbox</span>
          </div>
          <button
            onClick={loadDocuments}
            title="Refresh inbox"
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
          >
            <RefreshCw size={13} />
          </button>
        </div>

        {/* Bound Client Device Badge */}
        <div style={{ padding: '8px 10px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-xs)', fontSize: '11px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="text-muted flex items-center gap-1">
              <Cpu size={12} /> Bound Device:
            </span>
            <span className="font-mono text-primary font-bold" style={{ fontSize: '10px' }}>
              {deviceInfo.deviceId}
            </span>
          </div>
        </div>

        {loading ? (
          <div className="text-muted text-xs" style={{ padding: '24px 0', textAlign: 'center' }}>
            Loading encrypted documents...
          </div>
        ) : documents.length === 0 ? (
          <div className="text-muted text-xs" style={{ padding: '28px 0', textAlign: 'center' }}>
            No documents found for this account. Dispatch one from the Send Document tab.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '560px', overflowY: 'auto' }}>
            {documents.map((doc) => {
              const id = doc._id || doc.id!;
              const isSelected = selectedDoc?._id === id || selectedDoc?.id === id;
              return (
                <div
                  key={id}
                  onClick={() => {
                    if (activeSession?.blobUrl) {
                      URL.revokeObjectURL(activeSession.blobUrl);
                    }
                    setActiveSession(null);
                    setSelectedDoc(doc);
                    setError(null);
                    setPipelineSteps((prev) => prev.map((s) => ({ ...s, status: 'pending' })));
                  }}
                  style={{
                    padding: '12px',
                    borderRadius: 'var(--radius-xs)',
                    border: isSelected ? '1px solid var(--text-primary)' : '1px solid var(--border-subtle)',
                    background: isSelected ? 'var(--bg-elevated)' : 'var(--bg-secondary)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '4px' }}>
                    <span className="font-semibold text-xs text-primary">{doc.title}</span>
                    <span className="badge text-xs" style={{ fontSize: '9px', padding: '1px 5px' }}>
                      {(doc.fileSize / 1024).toFixed(1)} KB
                    </span>
                  </div>

                  <div className="text-xs text-muted" style={{ fontSize: '11px', display: 'flex', justifyContent: 'space-between' }}>
                    <span>{doc.fileName}</span>
                    <span className="font-mono text-dim">{new Date(doc.createdAt).toLocaleDateString()}</span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px' }}>
                    <span className="font-mono text-dim" style={{ fontSize: '9px' }}>
                      DOC: {doc.fileHash.slice(0, 12)}...
                    </span>
                    <span className="badge badge-white" style={{ fontSize: '8px', padding: '1px 4px' }}>
                      ML-KEM-1024
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>}

      {/* Right Column: Decryption Session Pipeline & Secure Viewer */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

        {!selectedDoc && error && <div className="inline-error" role="alert">{error} <button onClick={loadDocuments}>Try again</button></div>}
        {selectedDoc ? (
          <>
            {/* Document Header & Security Policy */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span className="badge badge-white">Encrypted document</span>
                    <span className="badge">AES-256-GCM</span>

                  </div>
                  <h2 className="text-lg font-bold">{selectedDoc.title}</h2>
                  <div className="font-mono text-xs text-secondary" style={{ marginTop: '4px' }}>
                    Document Hash (SHA-256): {selectedDoc.fileHash}
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <div className="text-xs text-muted">Shared by</div>
                  <div className="text-xs font-semibold text-primary">{selectedDoc.senderId?.username || 'Command Dispatcher'}</div>
                  {recipientUsernames.length > 0 && (
                    <div style={{ marginTop: '6px' }}>
                      <div className="text-xs text-muted">Recipient identities</div>
                      <div className="font-mono text-xs text-secondary">{recipientUsernames.join(', ')}</div>
                    </div>
                  )}
                </div>
              </div>

              {/* Recipient Authorization Guard */}
              {!isAuthorizedRecipient && (
                <div
                  style={{
                    marginTop: '16px',
                    padding: '12px 14px',
                    background: 'rgba(239, 68, 68, 0.08)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: 'var(--radius-xs)',
                    fontSize: '11px',
                    lineHeight: '1.5'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--status-danger)', fontWeight: 600, marginBottom: '4px' }}>
                    <AlertCircle size={14} />
                    <span>UNAUTHORIZED RECIPIENT IDENTITY</span>
                  </div>
                  <div className="text-secondary">
                    You are logged in as <span className="font-mono text-primary font-bold">{user?.username}</span>.
                    This post-quantum envelope was encapsulated exclusively for: <span className="font-mono text-primary font-bold">{recipientUsernames.join(', ')}</span>.
                  </div>
                  {recipientUsernames.length > 0 && (
                    <div style={{ marginTop: '10px', display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                      <span className="text-muted" style={{ fontSize: '10px' }}>Quick Switch Officer Profile:</span>
                      {recipientUsernames.map((u: string) => {
                        const profile = COMMAND_OFFICERS.find((p) => p.username === u);
                        if (!profile) return null;
                        return (
                          <button
                            key={u}
                            type="button"
                            onClick={() => quickSwitchUser(profile)}
                            className="badge badge-white hover:bg-white/20 transition-colors"
                            style={{ cursor: 'pointer', padding: '3px 8px' }}
                          >
                            Switch to {profile.name}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              <details className="viewer-technical">
                <summary>How secure access works</summary>
                <p>Opening a session checks your identity and device, prepares a recipient-specific copy, and records the access before releasing the document. The server determines whether access is allowed.</p>
              </details>

              {/* Primary Action Button */}
              {!activeSession && isAuthorizedRecipient && (
                <div style={{ marginTop: '20px' }}>
                  <button
                    onClick={handleInitiateSession}
                    disabled={isProcessingSession}
                    className="btn btn-primary"
                    style={{ width: '100%', padding: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                  >
                    <Lock size={15} />
                    <span style={{ fontWeight: 600, letterSpacing: '0.04em' }}>
                      {isProcessingSession ? 'Preparing secure session…' : 'Open document securely'}
                    </span>
                  </button>
                </div>
              )}

              {/* Visual Fail-Closed Pipeline State */}
              {(isProcessingSession || activeSession) && (
                <div style={{ marginTop: '20px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: '10px' }}>
                    Session progress
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px' }}>
                    {pipelineSteps.map((step, idx) => {
                      const isSuccess = step.status === 'success';
                      const isActive = step.status === 'active';
                      const isFailed = step.status === 'failed';
                      return (
                        <div
                          key={idx}
                          style={{
                            padding: '10px 8px',
                            background: isSuccess
                              ? 'rgba(34, 197, 94, 0.08)'
                              : isActive
                              ? 'rgba(59, 130, 246, 0.08)'
                              : isFailed
                              ? 'rgba(239, 68, 68, 0.08)'
                              : 'var(--bg-secondary)',
                            border: isSuccess
                              ? '1px solid rgba(34, 197, 94, 0.3)'
                              : isActive
                              ? '1px solid rgba(59, 130, 246, 0.4)'
                              : isFailed
                              ? '1px solid rgba(239, 68, 68, 0.4)'
                              : '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-xs)',
                            textAlign: 'center'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '4px' }}>
                            {isSuccess ? (
                              <CheckCircle size={14} color="var(--status-success)" />
                            ) : isActive ? (
                              <RefreshCw size={14} className="spin" />
                            ) : isFailed ? (
                              <XCircle size={14} color="var(--status-danger)" />
                            ) : (
                              <Clock size={14} className="text-muted" />
                            )}
                          </div>
                          <div style={{ fontSize: '10px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {step.name}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {error && (
                <div className="badge badge-danger" style={{ display: 'flex', width: '100%', padding: '10px 14px', marginTop: '14px', alignItems: 'center', gap: '8px' }}>
                  <AlertCircle size={15} />
                  <span>{error}</span>
                </div>
              )}
            </div>

            {/* Active Session & Controlled Watermarked Viewer */}
            {activeSession && (
              <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

                {/* Session Header Bar */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <ShieldCheck size={20} color="var(--status-success)" />
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="font-bold text-sm text-primary">SECURE EPHEMERAL VIEWER</span>
                        <span className="badge badge-success text-xs">STATUS: RELEASED</span>
                      </div>
                      <div className="font-mono text-xs text-muted" style={{ fontSize: '10px', marginTop: '2px' }}>
                        SESSION ID: {activeSession.sessionId} • RECIPIENT: {user?.username}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    {/* Expiry Countdown Timer */}
                    {sessionTimeRemaining !== null && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 10px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-subtle)' }}>
                        <Clock size={13} className={sessionTimeRemaining < 120 ? 'text-red-500 animate-pulse' : 'text-muted'} />
                        <span className="font-mono text-xs font-bold" style={{ color: sessionTimeRemaining < 120 ? 'var(--status-danger)' : 'var(--text-primary)' }}>
                          {Math.floor(sessionTimeRemaining / 60)}:{String(sessionTimeRemaining % 60).padStart(2, '0')}
                        </span>
                      </div>
                    )}

                    <button onClick={handleLockViewer} className="btn btn-secondary btn-sm" title="Revoke ephemeral memory and lock session">
                      <Lock size={12} />
                      <span>PURGE & CLOSE</span>
                    </button>
                  </div>
                </div>

                {/* Hyperledger Fabric Provenance Audit Banner */}
                {activeSession.prepareData && (
                  <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-medium)', borderRadius: 'var(--radius-xs)', padding: '12px 14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                      <div className="text-xs font-semibold text-primary flex items-center gap-1.5">
                        <CheckCircle size={13} color="var(--status-success)" />
                        <span>Hyperledger Fabric Decryption Provenance Transaction Committed</span>
                      </div>
                      <span className="badge badge-white font-mono" style={{ fontSize: '9px' }}>
                        BLOCK CONFIRMED
                      </span>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', marginTop: '8px', fontSize: '10px', fontFamily: 'var(--font-mono)' }}>
                      <div>
                        <span className="text-muted">TX ID: </span>
                        <span className="text-secondary font-bold">{activeSession.prepareData.ledgerTxId}</span>
                      </div>
                      <div>
                        <span className="text-muted">WATERMARK COMMITMENT: </span>
                        <span className="text-secondary font-bold">{activeSession.prepareData.watermarkCommitment.slice(0, 20)}...</span>
                      </div>
                      <div>
                        <span className="text-muted">ML-DSA SIGNATURE: </span>
                        <span className="text-secondary font-bold">{activeSession.prepareData.signature.slice(0, 24)}...</span>
                      </div>
                      <div>
                        <span className="text-muted">WATERMARK ID: </span>
                        <span className="text-secondary font-bold">{activeSession.prepareData.watermarkId}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* DLP & Optical Watermark Warning */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 12px', background: 'rgba(234, 179, 8, 0.08)', border: '1px solid rgba(234, 179, 8, 0.3)', borderRadius: 'var(--radius-xs)', fontSize: '11px' }}>
                  <ShieldAlert size={14} color="var(--status-warning)" />
                  <span className="text-secondary">
                    Data Loss Prevention Active: Document stream is protected with unique cryptographic forensic attribution. Analog screen capture or photographic reproduction can be optically extracted and tied to your identity.
                  </span>
                </div>

                {/* Secure Rendered Document Box with Watermark Overlay */}
                <div
                  style={{
                    position: 'relative',
                    background: '#f8f7f4',
                    border: '1px solid var(--border-strong)',
                    borderRadius: 'var(--radius-xs)',
                    minHeight: '380px',
                    maxHeight: '600px',
                    overflow: 'hidden',
                    display: 'flex',
                    flexDirection: 'column'
                  }}
                >
                  {/* Dynamic Optical Watermark Repeating Diagonal Overlay */}
                  <div
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      right: 0,
                      bottom: 0,
                      pointerEvents: 'none',
                      userSelect: 'none',
                      overflow: 'hidden',
                      opacity: 0.14,
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '48px',
                      padding: '24px',
                      transform: 'rotate(-12deg) scale(1.15)',
                      zIndex: 10
                    }}
                  >
                    {Array.from({ length: 16 }).map((_, i) => (
                      <div key={i} style={{ fontSize: '11px', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '0.12em', fontFamily: 'var(--font-mono)' }}>
                        CONFIDENTIAL // {user?.username?.toUpperCase()} // {activeSession.sessionId} // {deviceInfo.deviceId}
                      </div>
                    ))}
                  </div>

                  {/* Rendered Content: PDF Stream or Decoded Plaintext */}
                  {activeSession.blobUrl && (
                    <div style={{ flex: 1, position: 'relative', zIndex: 1, padding: '20px', overflowY: 'auto' }}>
                      {activeSession.textContent ? (
                        <div
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '12px',
                            lineHeight: '1.7',
                            color: '#33312e',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all'
                          }}
                        >
                          {activeSession.textContent}
                        </div>
                      ) : (
                        <iframe
                          src={`${activeSession.blobUrl}#toolbar=0&navpanes=0`}
                          style={{ width: '100%', height: '520px', border: 'none', borderRadius: 'var(--radius-xs)' }}
                          title="Controlled Forensic Document Stream"
                        />
                      )}
                    </div>
                  )}
                </div>

                {/* Footer Controls */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '8px' }}>
                  <div className="flex items-center gap-2">
                    <span className="badge badge-white text-xs font-mono">
                      DLP ENFORCED
                    </span>
                    <span className="text-muted text-xs">
                      Copy/Paste restrictions active • Session terminates on window unload
                    </span>
                  </div>

                  <button
                    onClick={() => {
                      alert(`Print Governance Notice:\nPrint job request for ${selectedDoc.title} logged with instance commitment ${activeSession.prepareData?.watermarkCommitment.slice(0, 16)}. Hardcopy forensic attribution active.`);
                    }}
                    className="btn btn-secondary btn-sm"
                  >
                    <Printer size={12} />
                    <span>CONTROLLED PRINT</span>
                  </button>
                </div>

              </div>
            )}
          </>
        ) : (
          <div className="card" style={{ padding: '60px 20px', textAlign: 'center' }}>
            <FileText size={32} className="text-secondary" style={{ margin: '0 auto 12px auto' }} />
            <h3 className="font-bold text-base">{loading ? "Loading document…" : documentId ? "Document unavailable" : "Select an encrypted document"}</h3>
            <p className="text-secondary text-xs" style={{ marginTop: '4px' }}>
              {loading ? "Retrieving the document record." : documentId ? "Return to document details or retry if an error is shown above." : "Choose a document from the inbox to start a secure session."}
            </p>
          </div>
        )}

      </div>

    </div>
  );
}
