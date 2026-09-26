'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '../../lib/authContext';
import { api } from '../../lib/api';
import { Key, Shield, Copy, Check, Download, AlertCircle, RefreshCw } from 'lucide-react';

export function KeyVaultConsole() {
  const { user, cachedPrivateKey, setCachedPrivateKey } = useAuth();
  const [serverKey, setServerKey] = useState<string>('');
  const [algorithm, setAlgorithm] = useState<string>('');
  const [inputKey, setInputKey] = useState(cachedPrivateKey || '');
  const [copiedUserKey, setCopiedUserKey] = useState(false);
  const [copiedServerKey, setCopiedServerKey] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    setInputKey(cachedPrivateKey || '');
  }, [cachedPrivateKey, user?.username]);

  useEffect(() => {
    async function loadServerKey() {
      try {
        const res = await api.getServerPublicKey();
        setServerKey(res.serverPublicKey);
        setAlgorithm(res.algorithm);
      } catch (err) {
        console.error('Failed to load server public key:', err);
      }
    }
    loadServerKey();
  }, []);

  const copyToClipboard = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const handleSavePrivateKey = () => {
    setCachedPrivateKey(inputKey.trim() || null);
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2000);
  };

  const handleDownloadPrivateKey = () => {
    if (!cachedPrivateKey) return;
    const blob = new Blob([cachedPrivateKey], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${user?.username || 'recipient'}_private_key.pem`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) minmax(320px, 1fr)', gap: '24px' }}>
      
      {/* Left: User Identity & RSA Keypair */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Key size={16} className="text-secondary" />
            <span className="uppercase-track text-primary font-bold">User Identity & RSA-2048 Keypair</span>
          </div>
          <span className="badge badge-white font-mono">{user?.role?.toUpperCase()}</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div>
            <span className="input-label">Identity Credential:</span>
            <div className="font-semibold text-sm text-primary">{user?.username} ({user?.email})</div>
          </div>

          {/* User Public Key */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <span className="input-label">Public Key (Stored on Ledger Node):</span>
              <button
                onClick={() => copyToClipboard(user?.publicKey || '', setCopiedUserKey)}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '10px', padding: '3px 8px' }}
              >
                {copiedUserKey ? <Check size={10} color="#34d399" /> : <Copy size={10} />}
                <span>{copiedUserKey ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>
            <div className="hex-box font-mono" style={{ fontSize: '10px', maxHeight: '110px' }}>
              {user?.publicKey || 'No public key registered for this user.'}
            </div>
          </div>

          {/* Private Key Session Cache */}
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span className="input-label">Recipient Private Key (Session Memory):</span>
              {cachedPrivateKey && (
                <button
                  onClick={handleDownloadPrivateKey}
                  className="btn btn-secondary btn-sm"
                  style={{ fontSize: '10px', padding: '3px 8px' }}
                >
                  <Download size={10} />
                  <span>EXPORT .PEM</span>
                </button>
              )}
            </div>

            <textarea
              rows={5}
              value={inputKey}
              onChange={(e) => setInputKey(e.target.value)}
              placeholder="Paste recipient RSA-2048 private key (PEM) to store in client-side session memory..."
              className="input-textarea input-mono"
              style={{ fontSize: '10px', resize: 'vertical' }}
            />

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
              <button
                onClick={handleSavePrivateKey}
                className="btn btn-primary btn-sm"
              >
                <span>{saveSuccess ? 'KEY LOADED IN SESSION' : 'SAVE TO CLIENT SESSION'}</span>
              </button>

              <span className="text-xs text-muted" style={{ fontSize: '10px' }}>
                Never transmitted or saved to backend DB.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Right: Server Provenance Signing Authority */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={16} className="text-secondary" />
            <span className="uppercase-track text-primary font-bold">Server Provenance Signing Authority</span>
          </div>
          <span className="badge font-mono">{algorithm || 'RSA-SHA256'}</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <p className="text-secondary text-xs">
            This public key represents the root signing authority for the immutable provenance ledger. Every block in the hash-chain is digitally signed using this keypair.
          </p>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <span className="input-label">Server Authority Public Key:</span>
              <button
                onClick={() => copyToClipboard(serverKey, setCopiedServerKey)}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '10px', padding: '3px 8px' }}
              >
                {copiedServerKey ? <Check size={10} color="#34d399" /> : <Copy size={10} />}
                <span>{copiedServerKey ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>
            <div className="hex-box font-mono" style={{ fontSize: '10px', maxHeight: '160px' }}>
              {serverKey || 'Querying server authority key...'}
            </div>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', padding: '12px' }}>
            <div className="font-semibold text-xs text-primary">Zero-Trust Cryptographic Guarantee</div>
            <div className="text-xs text-muted" style={{ marginTop: '4px', fontSize: '11px' }}>
              Any third-party auditor can verify the digital signature of every provenance log block offline using this public key without trusting the backend database.
            </div>
          </div>
        </div>
      </div>

    </div>
  );
}
