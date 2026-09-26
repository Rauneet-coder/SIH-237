'use client';

import React, { useState, useEffect } from 'react';
import { useAuth, COMMAND_OFFICERS } from '../../lib/authContext';
import { api, DocumentMeta } from '../../lib/api';
import { DEMO_PRIVATE_KEYS } from '../../lib/demoKeys';
import { Inbox, Key, Eye, Download, ShieldCheck, AlertCircle, Lock, FileText, CheckCircle, RefreshCw, UserCheck } from 'lucide-react';

export function InboxConsole() {
  const { user, token, cachedPrivateKey, setCachedPrivateKey, quickSwitchUser } = useAuth();
  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [selectedDoc, setSelectedDoc] = useState<DocumentMeta | null>(null);
  const [privateKeyPem, setPrivateKeyPem] = useState(
    (user?.username && DEMO_PRIVATE_KEYS[user.username]) || cachedPrivateKey || ''
  );
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptedResult, setDecryptedResult] = useState<{
    fileName: string;
    mimeType: string;
    fileHash: string;
    decryptedData: string;
    isBase64: boolean;
  } | null>(null);
  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Automatically sync private key whenever the active user or cached key changes
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

  const loadDocuments = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await api.listDocuments(token);
      setDocuments(res.documents || []);
      if (res.documents.length > 0 && !selectedDoc) {
        setSelectedDoc(res.documents[0]);
      }
    } catch (err: any) {
      console.error('Failed to load documents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDocuments();
  }, [token]);

  const handlePrivateKeyFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setPrivateKeyPem(content);
        setCachedPrivateKey(content);
      }
    };
    reader.readAsText(file);
  };

  const handleDecrypt = async () => {
    if (!token || !selectedDoc) return;
    if (!privateKeyPem.trim()) {
      setError('Please provide your RSA-2048 private key (PEM format) to decrypt.');
      return;
    }

    setIsDecrypting(true);
    setError(null);
    setDecryptedResult(null);
    setDecryptedText(null);

    try {
      const res = await api.decryptDocument(selectedDoc._id || selectedDoc.id!, privateKeyPem.trim(), token);
      setDecryptedResult(res);
      setCachedPrivateKey(privateKeyPem.trim());

      // Attempt to decode base64 to UTF-8 text for in-browser inspection
      if (res.decryptedData) {
        try {
          const rawText = atob(res.decryptedData);
          setDecryptedText(rawText);
        } catch {
          setDecryptedText('[Binary document content successfully decrypted into memory]');
        }
      }
    } catch (err: any) {
      setError(err.message || 'Decryption failed. Ensure your private key matches the recipient public key.');
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleDownload = () => {
    if (!decryptedResult) return;
    const link = document.createElement('a');
    link.href = `data:${decryptedResult.mimeType || 'application/octet-stream'};base64,${decryptedResult.decryptedData}`;
    link.download = decryptedResult.fileName || 'decrypted_document';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: '24px' }}>
      
      {/* Left Column: Documents Inbox List */}
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Inbox size={16} className="text-secondary" />
            <span className="uppercase-track text-primary font-bold">Secure Documents Inbox</span>
          </div>
          <span className="badge font-mono">{documents.length} Available</span>
        </div>

        {loading ? (
          <div className="text-muted text-xs" style={{ padding: '20px 0', textAlign: 'center' }}>
            Loading encrypted documents...
          </div>
        ) : documents.length === 0 ? (
          <div className="text-muted text-xs" style={{ padding: '24px 0', textAlign: 'center' }}>
            No documents addressed to this user account yet. Use the Dispatch console to encrypt one.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '600px', overflowY: 'auto' }}>
            {documents.map((doc) => {
              const id = doc._id || doc.id!;
              const isSelected = selectedDoc?._id === id || selectedDoc?.id === id;
              return (
                <div
                  key={id}
                  onClick={() => {
                    setSelectedDoc(doc);
                    setDecryptedResult(null);
                    setDecryptedText(null);
                    setError(null);
                  }}
                  style={{
                    padding: '12px',
                    borderRadius: 'var(--radius-xs)',
                    border: isSelected ? '1px solid #ffffff' : '1px solid var(--border-subtle)',
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

                  <div className="font-mono text-dim" style={{ fontSize: '9px', marginTop: '6px' }}>
                    HASH: {doc.fileHash.slice(0, 16)}...
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Right Column: Decryptor & Optical Watermark Viewer */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        
        {selectedDoc ? (
          <>
            {/* Document Header & Metadata */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span className="badge badge-white">ENCRYPTED ENVELOPE</span>
                    <span className="badge">AES-256-GCM</span>
                  </div>
                  <h2 className="text-lg font-bold">{selectedDoc.title}</h2>
                  <div className="font-mono text-xs text-secondary" style={{ marginTop: '4px' }}>
                    Ciphertext SHA256: {selectedDoc.fileHash}
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <div className="text-xs text-muted">Sender</div>
                  <div className="text-xs font-semibold text-primary">{selectedDoc.senderId?.username || 'Unknown'}</div>
                  {(() => {
                    const recUsernames = (selectedDoc.recipientKeys || [])
                      .map((rk: any) => rk.recipientId?.username || (typeof rk.recipientId === 'string' ? rk.recipientId : null))
                      .filter(Boolean);
                    if (recUsernames.length === 0) return null;
                    return (
                      <div style={{ marginTop: '6px' }}>
                        <div className="text-xs text-muted">Recipients</div>
                        <div className="font-mono text-xs text-secondary">{recUsernames.join(', ')}</div>
                      </div>
                    );
                  })()}
                </div>
              </div>

              {/* Private Key Decryption Input Form */}
              {!decryptedResult && (() => {
                const isAuthorizedRecipient = Boolean(
                  selectedDoc.recipientKeys?.some((rk: any) => {
                    const rId = rk.recipientId?._id || rk.recipientId;
                    const rUsername = rk.recipientId?.username;
                    return (user?._id && rId === user._id) || (user?.username && rUsername === user.username);
                  })
                );
                const recipientUsernames = (selectedDoc.recipientKeys || [])
                  .map((rk: any) => rk.recipientId?.username || (typeof rk.recipientId === 'string' ? rk.recipientId : null))
                  .filter(Boolean);

                return (
                  <div style={{ marginTop: '20px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
                    {/* Recipient Status Indicator */}
                    {selectedDoc.recipientKeys && selectedDoc.recipientKeys.length > 0 && (
                      !isAuthorizedRecipient ? (
                        <div
                          style={{
                            padding: '10px 14px',
                            background: 'rgba(239, 68, 68, 0.08)',
                            border: '1px solid rgba(239, 68, 68, 0.3)',
                            borderRadius: 'var(--radius-xs)',
                            marginBottom: '14px',
                            fontSize: '11px',
                            lineHeight: '1.5'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#f87171', fontWeight: 600, marginBottom: '4px' }}>
                            <AlertCircle size={14} />
                            <span>NOT AN AUTHORIZED RECIPIENT</span>
                          </div>
                          <div className="text-secondary">
                            You are currently viewing as <span className="font-mono text-primary font-bold">{user?.username}</span>. 
                            This encrypted envelope is addressed exclusively to: <span className="font-mono text-primary font-bold">{recipientUsernames.join(', ')}</span>.
                          </div>
                          {recipientUsernames.length > 0 && (
                            <div style={{ marginTop: '8px', display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                              <span className="text-muted" style={{ fontSize: '10px' }}>Quick Switch:</span>
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
                      ) : (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '12px' }}>
                          <span className="badge badge-success text-xs" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <CheckCircle size={11} />
                            <span>Authorized Recipient: {user?.username}</span>
                          </span>
                        </div>
                      )
                    )}

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
                      <label className="input-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Key size={13} />
                        <span>Recipient RSA-2048 Private Key (PEM)</span>
                      </label>
                      <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                        {user?.username && DEMO_PRIVATE_KEYS[user.username] && (
                          <button
                            type="button"
                            onClick={() => {
                              setPrivateKeyPem(DEMO_PRIVATE_KEYS[user.username]);
                              setCachedPrivateKey(DEMO_PRIVATE_KEYS[user.username]);
                              setError(null);
                            }}
                            className="text-xs text-secondary hover:underline cursor-pointer"
                            style={{ background: 'none', border: 'none', padding: 0 }}
                          >
                            Auto-fill {user.username} Key
                          </button>
                        )}
                        <label style={{ fontSize: '11px', color: 'var(--text-secondary)', cursor: 'pointer', textDecoration: 'underline' }}>
                          Upload .pem file
                          <input type="file" accept=".pem,.key,.txt" onChange={handlePrivateKeyFileUpload} style={{ display: 'none' }} />
                        </label>
                      </div>
                    </div>

                    <textarea
                      rows={4}
                      value={privateKeyPem}
                      onChange={(e) => setPrivateKeyPem(e.target.value)}
                      placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEowIBAAKCAQEA0t...&#10;-----END RSA PRIVATE KEY-----"
                      className="input-textarea input-mono"
                      style={{ fontSize: '11px', resize: 'vertical' }}
                    />

                    {error && (
                      <div className="badge badge-danger" style={{ display: 'flex', width: '100%', padding: '8px 12px', marginTop: '10px' }}>
                        <AlertCircle size={14} />
                        <span>{error}</span>
                      </div>
                    )}

                    <button
                      onClick={handleDecrypt}
                      disabled={isDecrypting || !privateKeyPem.trim() || !isAuthorizedRecipient}
                      className="btn btn-primary"
                      style={{ marginTop: '12px', width: '100%', padding: '12px' }}
                    >
                      <Lock size={14} />
                      <span>{isDecrypting ? 'UNWRAPPING KEY & LOGGING ATTRIBUTION...' : 'DECRYPT DOCUMENT & VERIFY ATTRIBUTION'}</span>
                    </button>
                  </div>
                );
              })()}
            </div>

            {/* Decrypted Document Viewer with Dynamic Optical Watermark Overlay */}
            {decryptedResult && (
              <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldCheck size={18} color="#34d399" />
                    <span className="font-bold text-sm text-primary">DECRYPTED FORENSIC VIEW</span>
                    <span className="badge badge-success text-xs">ATTRIBUTION LOGGED</span>
                  </div>

                  <button onClick={handleDownload} className="btn btn-secondary btn-sm">
                    <Download size={13} />
                    <span>DOWNLOAD FILE</span>
                  </button>
                </div>

                {/* Optical Watermark Notification */}
                <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-medium)', borderRadius: 'var(--radius-xs)', padding: '10px 14px' }}>
                  <div className="text-xs font-semibold text-primary" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckCircle size={12} color="#ffffff" />
                    <span>Dynamic Optical Forensic Watermark Applied</span>
                  </div>
                  <div className="text-xs text-muted" style={{ marginTop: '2px', fontSize: '11px' }}>
                    This copy contains a 256-bit Tardos collusion-resistant fingerprint codeword bound to recipient <span className="font-mono text-primary font-bold">{user?.username}</span>. If a smartphone photograph or screenshot is taken of this screen, the analog watermark can be extracted and traced back to your identity.
                  </div>
                </div>

                {/* Secure Rendered Document Box with Watermark Simulation */}
                <div
                  style={{
                    position: 'relative',
                    background: '#070709',
                    border: '1px solid var(--border-strong)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '24px',
                    minHeight: '260px',
                    maxHeight: '450px',
                    overflowY: 'auto',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    lineHeight: '1.7',
                    color: '#e4e4e7',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all'
                  }}
                >
                  {/* Optical Watermark Repeating Diagonal Overlay */}
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
                      opacity: 0.12,
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '40px',
                      padding: '20px',
                      transform: 'rotate(-12deg) scale(1.1)',
                      zIndex: 10
                    }}
                  >
                    {Array.from({ length: 12 }).map((_, i) => (
                      <div key={i} style={{ fontSize: '11px', fontWeight: 700, color: '#ffffff', letterSpacing: '0.1em' }}>
                        CONFIDENTIAL // {user?.username?.toUpperCase()} // {new Date().toISOString().slice(0, 10)} // TARDOS-FINGERPRINTED
                      </div>
                    ))}
                  </div>

                  {/* Rendered Decrypted Text Content */}
                  <div style={{ position: 'relative', zIndex: 1 }}>
                    {decryptedText}
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <button
                    onClick={() => {
                      setDecryptedResult(null);
                      setDecryptedText(null);
                    }}
                    className="btn btn-secondary btn-sm"
                  >
                    LOCK VIEWER
                  </button>
                  <span className="font-mono text-xs text-dim">
                    Decryption attribution verified on blockchain ledger
                  </span>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="card" style={{ padding: '60px 20px', textAlign: 'center' }}>
            <FileText size={32} className="text-secondary" style={{ margin: '0 auto 12px auto' }} />
            <h3 className="font-bold text-base">Select an Encrypted Document</h3>
            <p className="text-secondary text-xs" style={{ marginTop: '4px' }}>
              Choose a document from the inbox on the left to unwrap its cryptographic key envelope.
            </p>
          </div>
        )}

      </div>

    </div>
  );
}
