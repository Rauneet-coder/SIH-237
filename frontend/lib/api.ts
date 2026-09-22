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
  title: string;
  fileName: string;
  fileSize: number;
  fileHash: string;
  mimeType: string;
  senderId: User;
  recipientKeys: RecipientKeyEntry[];
  recipientCount?: number;
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
  login: (credentials: { username?: string; email?: string; password: string }) =>
    request<{ token: string; user: User }>('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    }),

  register: (payload: { username: string; email: string; password: string; role?: string }) =>
    request<{ message: string; user: User; privateKey: string }>('/auth/register', {
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
    request<{ serverPublicKey: string; algorithm: string }>('/provenance/server-key')
};
