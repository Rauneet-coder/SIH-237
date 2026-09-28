/**
 * SIH26237 — Cryptographic Attribution & Provenance API Client
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api';

export interface User {
  id: string;
  _id?: string;
  username: string;
  email: string;
  role: 'sender' | 'recipient' | 'investigator' | 'admin';
  publicKey?: string;
  createdAt?: string;
}

export interface RecipientKeyEntry {
  recipientId: User;
  encryptedSymmetricKey: string;
}

export interface DocumentMeta {
  _id: string;
  id?: string;
  documentId?: string;
  title: string;
  fileName: string;
  fileSize: number;
  fileHash: string;
  structuralFingerprint?: string;
  storagePath?: string;
  mimeType: string;
  classification?: string;
  validFrom?: string;
  validUntil?: string;
  senderId: User;
  recipientKeys: RecipientKeyEntry[];
  recipientCount?: number;
  keyEnvelopes?: Array<{ recipientId: string }>;
  myEncryptedKey?: string;
  createdAt: string;
}

export interface ProvenanceLogEntry {
  _id: string;
  sequenceNumber: number;
  prevHash: string;
  entryHash: string;
  signature: string;
  docId: { _id: string; title: string; fileName: string; fileHash: string };
  recipientId: { _id: string; username: string; email: string; role: string };
  action: 'ENCRYPT_UPLOAD' | 'DECRYPT_SUCCESS' | 'DECRYPT_FAILURE';
  status: 'SUCCESS' | 'FAILURE';
  failureReason?: string;
  fingerprintCodewordHash?: string;
  timestamp: string;
}

export interface VerificationReport {
  valid: boolean;
  tampered: boolean;
  totalBlocks: number;
  genesisValid: boolean;
  chainIntegrityValid: boolean;
  allSignaturesValid: boolean;
  tamperedSequences: number[];
  verifiedAt: string;
  message?: string;
}

export interface AccusedRecipient {
  recipientId: string;
  username: string;
  email: string;
  score: number;
  threshold: number;
  confidencePercentage: number;
}

export interface TraitorTracingReport {
  collusionDetected: boolean;
  colluderCount: number;
  threshold: number;
  accusedRecipients: AccusedRecipient[];
  rankedCandidates: Array<{
    recipientId: string;
    username: string;
    email: string;
    score: number;
  }>;
  analysisTimestamp: string;
}

export interface PrepareSessionResponse {
  success: boolean;
  status: string;
  sessionId: string;
  watermarkId: string;
  watermarkCommitment: string;
  eventDigest: string;
  signature: string;
  ledgerTxId: string;
}

export interface DecryptionSessionResponse {
  success: boolean;
  sessionId: string;
  status: string;
  expiresAt: string;
}

async function request<T>(endpoint: string, options: RequestInit = {}, token?: string | null): Promise<T> {
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> || {})
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers
  });

  const contentType = response.headers.get('content-type');
  let data;
  if (contentType && contentType.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const errorMsg = data && typeof data === 'object' && 'error' in data 
      ? data.error 
      : `HTTP ${response.status}: ${response.statusText}`;
    throw new Error(errorMsg);
  }

  return data as T;
}

export const api = {
  // Auth
  login: (credentials: { username?: string; email?: string; password: string; deviceId?: string; deviceFingerprint?: string }) =>
    request<{ token: string; user: User }>('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    }),

  register: (payload: { username: string; email: string; password: string; role?: string; deviceId?: string; deviceFingerprint?: string; platform?: string }) =>
    request<{ message: string; user: User; privateKey?: string }>('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }),

  getMe: (token: string) =>
    request<{ user: User }>('/auth/me', {}, token),

  getRecipients: (token: string) =>
    request<{ recipients: User[] }>('/auth/recipients', {}, token),

  // Documents
  listDocuments: (token: string) =>
    request<{ documents: DocumentMeta[] }>('/documents', {}, token),

  getDocument: (id: string, token: string) =>
    request<{ document: DocumentMeta }> (`/documents/${id}`, {}, token),

  uploadDocument: (formData: FormData, token: string) =>
    request<{ message: string; document: DocumentMeta }>('/documents/upload', {
      method: 'POST',
      body: formData
    }, token),

  decryptDocument: (id: string, privateKey: string, token: string) =>
    request<{
      message: string;
      documentId: string;
      fileName: string;
      mimeType: string;
      fileHash: string;
      decryptedData: string;
      isBase64: boolean;
    }>(`/documents/${id}/decrypt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ privateKey })
    }, token),

  // Traitor Tracing & Collusion
  traceCollusion: (id: string, payload: { watermarkCodeword?: string; leakedContent?: string; isBase64?: boolean }, token: string) =>
    request<{
      documentId: string;
      documentTitle: string;
      report: TraitorTracingReport;
      reportDigest: string;
      serverSignature: string;
      serverPublicKey: string;
    }>(`/documents/${id}/trace`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }, token),

  simulateCollusion: (id: string, colluderIds: string[], strategy: string, token: string) =>
    request<{
      documentId: string;
      colluderCount: number;
      collusionStrategy: string;
      syntheticWatermark: string;
      report: TraitorTracingReport;
      serverSignature: string;
    }>(`/documents/${id}/simulate-collusion`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ colluderIds, strategy })
    }, token),

  // Provenance Ledger
  listLogs: (params: Record<string, string> = {}, token: string) => {
    const query = new URLSearchParams(params).toString();
    return request<{ total: number; logs: ProvenanceLogEntry[] }>(`/provenance/logs${query ? `?${query}` : ''}`, {}, token);
  },

  verifyChain: () =>
    request<{ report: VerificationReport; serverPublicKey: string }>('/provenance/verify'),

  getServerPublicKey: () =>
    request<{ serverPublicKey: string; algorithm: string }>('/provenance/server-key'),

  // Decryption Sessions (Post-Quantum Fail-Closed Pipeline)
  createSession: (documentId: string, deviceId: string, token: string) =>
    request<{ success: boolean; sessionId: string; status: string; expiresAt: string }>('/sessions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-device-id': deviceId
      },
      body: JSON.stringify({ documentId, deviceId })
    }, token),

  prepareSession: (sessionId: string, deviceId: string, token: string) =>
    request<{
      success: boolean;
      status: string;
      sessionId: string;
      watermarkId: string;
      watermarkCommitment: string;
      eventDigest: string;
      signature: string;
      ledgerTxId: string;
    }>(`/sessions/${sessionId}/prepare`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-device-id': deviceId
      },
      body: JSON.stringify({ deviceId })
    }, token),

  getSessionStatus: (sessionId: string, token: string) =>
    request<{
      success: boolean;
      session: {
        sessionId: string;
        documentId: string;
        recipientId: string;
        status: string;
        watermarkId?: string;
        watermarkCommitment?: string;
        ledgerTxId?: string;
        startedAt: string;
        expiresAt: string;
        failureReason?: string;
      };
    }>(`/sessions/${sessionId}/status`, {}, token),

  renderSessionDocument: async (sessionId: string, deviceId: string, token: string): Promise<Blob> => {
    const res = await fetch(`${API_BASE_URL}/sessions/${sessionId}/render`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'x-device-id': deviceId
      }
    });
    if (!res.ok) {
      const errText = await res.text();
      let errMsg = `HTTP ${res.status}: Failed to render document`;
      try {
        const errObj = JSON.parse(errText);
        errMsg = errObj.error || errMsg;
      } catch {}
      throw new Error(errMsg);
    }
    return await res.blob();
  },

  closeSession: (sessionId: string, token: string) =>
    request<{ success: boolean; sessionId: string; status: string; message: string }>(`/sessions/${sessionId}/close`, {
      method: 'POST'
    }, token),

  // Forensic Investigation & Leak Verification
  extractWatermark: (formData: FormData, token: string) =>
    request<{ success: boolean; extraction: any }>('/forensics/extract', {
      method: 'POST',
      body: formData
    }, token),

  verifyForensicEvidence: (payload: { watermarkId?: string; watermarkCommitment?: string; eventId?: string; documentHash?: string }, token: string) =>
    request<{ success: boolean; verification: any }>('/forensics/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }, token),

  investigateLeak: (formData: FormData, token: string) =>
    request<{ success: boolean; extraction: any; verification: any }>('/forensics/investigate', {
      method: 'POST',
      body: formData
    }, token),

  // Device Binding
  registerDevice: (payload: { deviceId: string; deviceFingerprint: string; platform?: string }, token: string) =>
    request<{ success: boolean; device: any }>('/auth/devices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }, token),

  listDevices: (token: string) =>
    request<{ success: boolean; devices: any[] }>('/auth/devices', {}, token)
};
