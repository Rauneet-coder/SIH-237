'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '../../lib/authContext';
import { api, User, DocumentMeta } from '../../lib/api';
import { Upload, Shield, CheckCircle, FileText, Lock, Users, ArrowRight, AlertCircle, Edit3, ShieldAlert } from 'lucide-react';

interface DispatchConsoleProps {
  onSuccess?: () => void;
}

export function DispatchConsole({ onSuccess }: DispatchConsoleProps) {
  const { user, token } = useAuth();
  const [recipients, setRecipients] = useState<User[]>([]);
  const [selectedRecipientIds, setSelectedRecipientIds] = useState<string[]>([]);
  const [docSourceMode, setDocSourceMode] = useState<'upload' | 'compose'>('compose');
  const [title, setTitle] = useState('Operational Security Directive // Alpha-7');
  const [classification, setClassification] = useState('TOP SECRET');
  const [textContent, setTextContent] = useState(
    'MINISTRY OF DEFENCE // CONFIDENTIAL MEMO\n\n' +
    'Subject: Sector 4 Deployment & Cryptographic Key Rollover Schedule\n\n' +
    '1. All units under Command Alpha must verify their local node public keys.\n' +
    '2. Decryption attempts are logged immutably on the signed provenance ledger.\n' +
    '3. Any unauthorized leakage or screen capture will be subjected to Tardos traitor tracing attribution.\n\n' +
    'Auth Code: DEF-7749-SEC'
  );
  const [file, setFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [isHashing, setIsHashing] = useState(false);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [uploadedDoc, setUploadedDoc] = useState<DocumentMeta | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Auto-hash text content when composing
  useEffect(() => {
    if (docSourceMode === 'compose' && textContent) {
      const computeTextHash = async () => {
        setIsHashing(true);
        try {
          const encoder = new TextEncoder();
          const data = encoder.encode(textContent);
          const hashBuffer = await crypto.subtle.digest('SHA-256', data);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
          setFileHash(hashHex);
        } catch (err) {
          console.error('Hash calculation error:', err);
        } finally {
          setIsHashing(false);
        }
      };
      computeTextHash();
    }
  }, [docSourceMode, textContent]);

  useEffect(() => {
    async function loadRecipients() {
      if (!token) return;
      try {
        const res = await api.getRecipients(token);
        // Exclude current user from recipient list
        const others = res.recipients.filter((r) => r.username !== user?.username);
        setRecipients(others);
        // Pre-select first two recipients for demo convenience
        if (others.length >= 2) {
          setSelectedRecipientIds([others[0].id || others[0]._id!, others[1].id || others[1]._id!]);
        }
      } catch (err: any) {
        console.error('Failed to load recipients:', err);
      }
    }
    loadRecipients();
  }, [token, user]);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile) return;

    setFile(selectedFile);
    if (!title) setTitle(selectedFile.name.replace(/\.[^/.]+$/, ''));

    // Compute SHA-256 hash client-side
    setIsHashing(true);
    setFileHash(null);
    try {
      const buffer = await selectedFile.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      setFileHash(hashHex);
    } catch (err) {
      console.error('Client-side hash error:', err);
    } finally {
      setIsHashing(false);
    }
  };

  const toggleRecipient = (id: string) => {
    setSelectedRecipientIds((prev) =>
      prev.includes(id) ? prev.filter((r) => r !== id) : [...prev, id]
    );
  };

  const handleDispatch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      setError('You must be logged in to dispatch documents.');
      return;
    }
    if (selectedRecipientIds.length === 0) {
      setError('Please select at least one recipient sub-user.');
      return;
    }

    let fileToSend: File | null = null;
    if (docSourceMode === 'upload') {
      if (!file) {
        setError('Please select a document file to encrypt and dispatch.');
        return;
      }
      fileToSend = file;
    } else {
      if (!textContent.trim()) {
        setError('Please enter document text content to compose.');
        return;
      }
      const safeTitle = (title || 'secure_directive').replace(/\s+/g, '_');
      fileToSend = new File([textContent], `${safeTitle}.txt`, { type: 'text/plain' });
    }

    setIsEncrypting(true);
    setError(null);
    setUploadedDoc(null);

    try {
      const formData = new FormData();
      formData.append('file', fileToSend);
      formData.append('title', title || fileToSend.name);
      formData.append('recipients', JSON.stringify(selectedRecipientIds));

      const res = await api.uploadDocument(formData, token);
      setUploadedDoc(res.document);
      if (onSuccess) onSuccess();
    } catch (err: any) {
      setError(err.message || 'Encryption and dispatch failed.');
    } finally {
      setIsEncrypting(false);
    }
  };

  const isSenderOrAdmin = user?.role === 'sender' || user?.role === 'admin';

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) minmax(320px, 1fr)', gap: '24px' }}>
      
      {/* Left Form: Dispatch Controls */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={16} className="text-secondary" />
            <span className="uppercase-track text-primary font-bold">Admin / Sender Document Dispatch</span>
          </div>
          <span className="badge badge-white font-mono">RBAC: SENDER / ADMIN</span>
        </div>

        {!isSenderOrAdmin && (
          <div style={{ background: '#1c150c', border: '1px solid #78350f', borderRadius: 'var(--radius-xs)', padding: '10px 12px', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fbbf24', fontSize: '11px', fontWeight: 600 }}>
              <ShieldAlert size={14} />
              <span>RBAC NOTICE: Currently Logged In as [{user?.role?.toUpperCase()}]</span>
            </div>
            <div className="text-muted text-xs" style={{ fontSize: '10px', marginTop: '2px' }}>
              In operational deployments, only SENDER or ADMIN roles create and dispatch documents. Switch to Col. Sharma in the top bar to evaluate with full Sender authority.
            </div>
          </div>
        )}

        {error && (
          <div className="badge badge-danger" style={{ display: 'flex', width: '100%', padding: '8px 12px', marginBottom: '16px', borderRadius: 'var(--radius-xs)' }}>
            <AlertCircle size={14} />
            <span>{error}</span>
          </div>
        )}

        {/* Source Mode Toggle: Compose Text vs Upload File */}
        <div style={{ display: 'flex', gap: '6px', marginBottom: '16px' }}>
          <button
            type="button"
            onClick={() => setDocSourceMode('compose')}
            className={`btn btn-sm ${docSourceMode === 'compose' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ flex: 1 }}
          >
            <Edit3 size={13} />
            <span>COMPOSE TEXT DOCUMENT</span>
          </button>
          <button
            type="button"
            onClick={() => setDocSourceMode('upload')}
            className={`btn btn-sm ${docSourceMode === 'upload' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ flex: 1 }}
          >
            <Upload size={13} />
            <span>UPLOAD EXISTING FILE</span>
          </button>
        </div>

        <form onSubmit={handleDispatch}>
          
          {/* Classification Selector */}
          <div className="input-group">
            <label className="input-label">Security Classification</label>
            <select
              value={classification}
              onChange={(e) => setClassification(e.target.value)}
              className="input-select font-mono"
            >
              <option value="RESTRICTED">DEFENCE // RESTRICTED</option>
              <option value="CONFIDENTIAL">DEFENCE // CONFIDENTIAL</option>
              <option value="SECRET">DEFENCE // SECRET</option>
              <option value="TOP SECRET">DEFENCE // TOP SECRET (PQC ENCAPSULATED)</option>
            </select>
          </div>

          {/* Document Title */}
          <div className="input-group">
            <label className="input-label">Document Title / Subject</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g., Op-Trident Operational Blueprint"
              className="input-text"
              required
            />
          </div>

          {/* Document Body: Text Composer or File Upload */}
          {docSourceMode === 'compose' ? (
            <div className="input-group">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <label className="input-label">Classified Text Content (In-Browser Document Creator)</label>
                <span className="font-mono text-xs text-muted">{textContent.length} Bytes</span>
              </div>
              <textarea
                rows={6}
                value={textContent}
                onChange={(e) => setTextContent(e.target.value)}
                placeholder="Type confidential document text to encrypt and distribute..."
                className="input-textarea font-mono"
                style={{ fontSize: '11px', resize: 'vertical', lineHeight: '1.6' }}
                required
              />
            </div>
          ) : (
            <div className="input-group">
              <label className="input-label">Secure Document Payload File</label>
              <div
                style={{
                  border: '1px dashed var(--border-strong)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '20px',
                  textAlign: 'center',
                  background: 'var(--bg-input)',
                  cursor: 'pointer'
                }}
                onClick={() => document.getElementById('file-upload-input')?.click()}
              >
                <Upload size={24} className="text-secondary" style={{ margin: '0 auto 8px auto' }} />
                <div className="text-sm font-semibold text-primary">
                  {file ? file.name : 'Choose secure document to encrypt'}
                </div>
                <div className="text-xs text-muted" style={{ marginTop: '4px' }}>
                  {file ? `${(file.size / 1024).toFixed(1)} KB — Click to change` : 'Supports PDF, TXT, DOCX, BIN (Max 50MB)'}
                </div>
                <input
                  id="file-upload-input"
                  type="file"
                  style={{ display: 'none' }}
                  onChange={handleFileChange}
                />
              </div>
            </div>
          )}

          {/* Recipient Sub-Users Selection */}
          <div className="input-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label className="input-label">Target Sub-Users / Recipients ({selectedRecipientIds.length} Selected)</label>
              <span className="text-xs text-muted font-mono">{recipients.length} Registered</span>
            </div>

            <div
              style={{
                maxHeight: '180px',
                overflowY: 'auto',
                border: '1px solid var(--border-medium)',
                borderRadius: 'var(--radius-xs)',
                background: 'var(--bg-input)'
              }}
            >
              {recipients.length === 0 ? (
                <div style={{ padding: '16px', textAlign: 'center' }} className="text-xs text-muted">
                  No other recipient sub-users registered on this node.
                </div>
              ) : (
                recipients.map((r) => {
                  const id = r.id || r._id!;
                  const isSelected = selectedRecipientIds.includes(id);
                  return (
                    <div
                      key={id}
                      onClick={() => toggleRecipient(id)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 12px',
                        borderBottom: '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        background: isSelected ? 'rgba(255,255,255,0.05)' : 'transparent'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          style={{ cursor: 'pointer' }}
                        />
                        <div>
                          <div className="font-semibold text-xs text-primary">{r.username}</div>
                          <div className="text-muted font-mono text-xs" style={{ fontSize: '10px' }}>{r.email}</div>
                        </div>
                      </div>
                      <span className="badge font-mono" style={{ fontSize: '9px' }}>
                        {r.role.toUpperCase()}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isEncrypting || (docSourceMode === 'upload' && !file) || (docSourceMode === 'compose' && !textContent.trim()) || selectedRecipientIds.length === 0}
            className="btn btn-primary"
            style={{ width: '100%', marginTop: '8px', padding: '12px' }}
          >
            <Lock size={14} />
            <span>{isEncrypting ? 'ENCRYPTING & DISTRIBUTING...' : 'ENCRYPT & DISPATCH TO SUB-USERS'}</span>
          </button>
        </form>
      </div>

      {/* Right Panel: Cryptographic Telemetry & Pipeline Inspector */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        
        {/* Encryption Pipeline Visualization */}
        <div className="card">
          <div className="uppercase-track text-muted" style={{ marginBottom: '14px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
            Hybrid Encryption Sequence (Native node:crypto)
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
              <div className="badge badge-white font-mono" style={{ padding: '2px 6px' }}>1</div>
              <div>
                <div className="font-semibold text-xs text-primary">Pre-Encryption Integrity Digest</div>
                <div className="text-xs text-muted">Plaintext hashed with SHA-256 prior to ciphertext transformation.</div>
                {fileHash && (
                  <div className="hex-box font-mono" style={{ marginTop: '6px', fontSize: '10px' }}>
                    SHA256: {fileHash}
                  </div>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
              <div className="badge badge-white font-mono" style={{ padding: '2px 6px' }}>2</div>
              <div>
                <div className="font-semibold text-xs text-primary">AES-256-GCM Symmetric Key Generation</div>
                <div className="text-xs text-muted">Fresh 32-byte symmetric key + 12-byte cryptographically random IV per document.</div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
              <div className="badge badge-white font-mono" style={{ padding: '2px 6px' }}>3</div>
              <div>
                <div className="font-semibold text-xs text-primary">RSA-OAEP Key Encapsulation ({selectedRecipientIds.length} Copies)</div>
                <div className="text-xs text-muted">Document symmetric key wrapped individually under each recipient&apos;s RSA public key using SHA-256 hash padding.</div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
              <div className="badge badge-white font-mono" style={{ padding: '2px 6px' }}>4</div>
              <div>
                <div className="font-semibold text-xs text-primary">Immutable Provenance Chain Logging</div>
                <div className="text-xs text-muted">Dispatch event recorded with sequence hash and signed by server authority key.</div>
              </div>
            </div>
          </div>
        </div>

        {/* Confirmation Output */}
        {uploadedDoc && (
          <div className="card card-elevated" style={{ border: '1px solid #ffffff' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <CheckCircle size={16} color="#34d399" />
              <span className="font-bold text-sm text-primary">DOCUMENT DISPATCHED & LOGGED</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">Document ID:</span>
                <span className="font-mono text-primary">{uploadedDoc._id || uploadedDoc.id}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">File Name:</span>
                <span className="text-primary font-semibold">{uploadedDoc.fileName}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">Encrypted Envelopes:</span>
                <span className="font-mono text-primary font-bold">{uploadedDoc.recipientKeys?.length || selectedRecipientIds.length} Recipient(s)</span>
              </div>
              <div style={{ marginTop: '8px' }}>
                <span className="text-muted text-xs">Immutable Ciphertext Hash:</span>
                <div className="hex-box font-mono" style={{ fontSize: '10px', marginTop: '4px' }}>
                  {uploadedDoc.fileHash}
                </div>
              </div>
            </div>
          </div>
        )}

      </div>

    </div>
  );
}
