"use client";
import React, { useState } from "react";
import {
  Check,
  FileText,
  LockKeyhole,
  Loader2,
  Send,
  Key,
  Database,
  FileCheck,
  Copy,
  ExternalLink,
  ShieldCheck,
  Lock,
  type LucideIcon,
} from "lucide-react";
import { DocumentMeta } from "../lib/api";

export interface StageDefinition {
  num: number;
  label: string;
  detail: string;
  algorithm: string;
  icon: LucideIcon;
}

export const DISPATCH_STAGES: StageDefinition[] = [
  {
    num: 1,
    label: "Pre-Encryption Integrity Digest & Layout Extraction",
    detail: "Computing SHA-256 pre-encryption digest & extracting structural content tokens.",
    algorithm: "SHA-256 + AST Tokenizer",
    icon: FileCheck,
  },
  {
    num: 2,
    label: "AES-256-GCM Symmetric Key Generation & Zeroization",
    detail: "Generating fresh 32-byte DEK & 12-byte IV; key securely zeroized in RAM immediately after cipher.",
    algorithm: "AES-256-GCM (NIST FIPS 197)",
    icon: LockKeyhole,
  },
  {
    num: 3,
    label: "Post-Quantum Multi-Recipient Key Encapsulation",
    detail: "Encapsulating document DEK individually per recipient with SHA-256 OAEP / ML-KEM-1024 padding.",
    algorithm: "ML-KEM-1024 / RSA-OAEP",
    icon: Key,
  },
  {
    num: 4,
    label: "Filesystem Vault Storage Isolation (POSIX 0600)",
    detail: "Writing ciphertext directly to disk vault with 0600 mode; duplicate database blobs purged.",
    algorithm: "POSIX 0600 Disk Vault",
    icon: Database,
  },
  {
    num: 5,
    label: "Immutable Provenance Ledger & Server Signature",
    detail: "Committing canonical RFC 8785 event with sequence hash and server authority signature.",
    algorithm: "RFC 8785 + ML-DSA-65",
    icon: Send,
  },
];

export function DispatchProgress({
  currentStage = 0,
  complete = false,
  recipients = 1,
  error = "",
}: {
  currentStage?: number;
  complete: boolean;
  recipients: number;
  error?: string;
}) {
  return (
    <ol
      className={`dispatch-timeline ${complete ? "is-complete" : ""}`}
      aria-label="Document delivery cryptographic pipeline"
    >
      {DISPATCH_STAGES.map((stage, idx) => {
        const Icon = stage.icon;
        const isDone = complete || idx < currentStage;
        const isActive = !complete && idx === currentStage && !error;
        const isFailed = !complete && idx === currentStage && !!error;
        const stateClass = isDone
          ? "stage-done"
          : isActive
          ? "stage-active"
          : isFailed
          ? "stage-failed"
          : "stage-waiting";

        return (
          <li
            key={stage.num}
            className={`dispatch-stage ${stateClass}`}
            aria-current={isActive ? "step" : undefined}
          >
            <span className="dispatch-stage-marker" aria-hidden="true">
              {isDone ? (
                <Check size={15} strokeWidth={2.5} />
              ) : isActive ? (
                <Loader2 size={15} className="spin" />
              ) : (
                <Icon size={15} />
              )}
            </span>
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "6px" }}>
                <strong>
                  {stage.num}. {stage.label}
                </strong>
                <span className="dispatch-algo-tag">{stage.algorithm}</span>
              </div>
              <small>
                {stage.num === 3
                  ? `Encapsulating document DEK individually for ${recipients} recipient${
                      recipients === 1 ? "" : "s"
                    } with SHA-256 OAEP / ML-KEM-1024 padding.`
                  : stage.detail}
              </small>
            </div>
            <span className="dispatch-stage-state">
              {isDone
                ? "Complete"
                : isActive
                ? "In progress"
                : isFailed
                ? "Failed"
                : "Pending"}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

export function DispatchAnimation({ complete }: { complete: boolean }) {
  return (
    <div
      className={`dispatch-animation ${complete ? "is-complete" : ""}`}
      aria-hidden="true"
    >
      <span className="dispatch-orbit orbit-one" />
      <span className="dispatch-orbit orbit-two" />
      <div className="dispatch-paper">
        <FileText size={35} strokeWidth={1.3} />
        <span className="dispatch-seal">
          {complete ? <ShieldCheck size={19} /> : <LockKeyhole size={17} />}
        </span>
      </div>
      {!complete && (
        <div className="dispatch-transfer">
          <span />
          <span />
          <span />
        </div>
      )}
    </div>
  );
}

export function DispatchTelemetry({
  document,
  recipientNames = [],
}: {
  document: DocumentMeta;
  recipientNames: string[];
}) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const docId = document.documentId || document.id || document._id;
  const classification = document.classification || "CONFIDENTIAL";
  const fileHash = document.fileHash || "";
  const structuralFingerprint = document.structuralFingerprint || "";
  const storagePath = document.storagePath || `storage/encrypted/${docId}.enc`;

  return (
    <div className="dispatch-telemetry-card">
      <div className="dispatch-telemetry-header">
        <span>Cryptographic Audit Telemetry</span>
        <span
          className="badge"
          style={{
            background:
              classification === "TOP_SECRET"
                ? "rgba(194,70,55,0.12)"
                : "rgba(95,121,82,0.12)",
            color:
              classification === "TOP_SECRET"
                ? "var(--status-danger)"
                : "var(--status-success)",
            borderColor:
              classification === "TOP_SECRET"
                ? "rgba(194,70,55,0.3)"
                : "rgba(95,121,82,0.3)",
            fontSize: "10px",
            fontWeight: 700,
          }}
        >
          {classification}
        </span>
      </div>

      <div className="dispatch-telemetry-grid">
        <div className="telemetry-item">
          <div className="telemetry-label">
            <span>Canonical Document ID</span>
          </div>
          <div className="telemetry-value-row">
            <div className="telemetry-hex" style={{ fontWeight: 600 }}>{docId}</div>
            <button
              type="button"
              className="telemetry-copy-btn"
              onClick={() => copyToClipboard(docId, "docId")}
              title="Copy Document ID"
            >
              <Copy size={11} />
              {copiedKey === "docId" ? "Copied!" : "Copy"}
            </button>
          </div>
        </div>

        {fileHash && (
          <div className="telemetry-item">
            <div className="telemetry-label">
              <span>Pre-Encryption SHA-256 Digest</span>
              <span className="dispatch-algo-tag" style={{ margin: 0 }}>NIST FIPS 180-4</span>
            </div>
            <div className="telemetry-value-row">
              <div className="telemetry-hex">{fileHash}</div>
              <button
                type="button"
                className="telemetry-copy-btn"
                onClick={() => copyToClipboard(fileHash, "fileHash")}
                title="Copy SHA-256 Hash"
              >
                <Copy size={11} />
                {copiedKey === "fileHash" ? "Copied!" : "Copy"}
              </button>
            </div>
          </div>
        )}

        {structuralFingerprint && (
          <div className="telemetry-item">
            <div className="telemetry-label">
              <span>Structural Layout Fingerprint (Anti-Fraud)</span>
              <span className="dispatch-algo-tag" style={{ margin: 0 }}>AST Word Tokenizer</span>
            </div>
            <div className="telemetry-value-row">
              <div className="telemetry-hex">{structuralFingerprint}</div>
              <button
                type="button"
                className="telemetry-copy-btn"
                onClick={() => copyToClipboard(structuralFingerprint, "fp")}
                title="Copy Structural Fingerprint"
              >
                <Copy size={11} />
                {copiedKey === "fp" ? "Copied!" : "Copy"}
              </button>
            </div>
          </div>
        )}

        <div className="telemetry-item">
          <div className="telemetry-label">
            <span>Encapsulated Envelopes & Storage</span>
          </div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", fontSize: "11px", marginTop: "2px" }}>
            <span className="badge" style={{ background: "var(--bg-card)", border: "1px solid var(--border-medium)" }}>
              🔒 {document.recipientCount || recipientNames.length} Recipient Envelope(s)
            </span>
            <span className="badge" style={{ background: "var(--bg-card)", border: "1px solid var(--border-medium)", fontFamily: "var(--font-mono)" }}>
              🗄️ {storagePath}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export function PipelinePreview({ recipientCount }: { recipientCount: number }) {
  return (
    <div className="pipeline-preview-card">
      <div className="pipeline-preview-title">
        <ShieldCheck size={14} color="var(--status-success)" />
        <span>Hybrid Cryptographic Pipeline Guarantees</span>
      </div>
      <div className="pipeline-preview-list">
        <div className="pipeline-preview-step">
          <div className="pipeline-preview-left">
            <span className="pipeline-preview-num">1</span>
            <span>Pre-Encryption SHA-256 Digest & AST Layout Tokenizer</span>
          </div>
          <span className="dispatch-algo-tag">SHA-256</span>
        </div>
        <div className="pipeline-preview-step">
          <div className="pipeline-preview-left">
            <span className="pipeline-preview-num">2</span>
            <span>AES-256-GCM Symmetric Cipher with 32-byte DEK zeroization</span>
          </div>
          <span className="dispatch-algo-tag">AES-256-GCM</span>
        </div>
        <div className="pipeline-preview-step">
          <div className="pipeline-preview-left">
            <span className="pipeline-preview-num">3</span>
            <span>Key Encapsulation wrapped individually for {recipientCount} recipient(s)</span>
          </div>
          <span className="dispatch-algo-tag">ML-KEM-1024</span>
        </div>
        <div className="pipeline-preview-step">
          <div className="pipeline-preview-left">
            <span className="pipeline-preview-num">4</span>
            <span>POSIX 0600 storage vault; zero ciphertext in database</span>
          </div>
          <span className="dispatch-algo-tag">MODE 0600</span>
        </div>
        <div className="pipeline-preview-step">
          <div className="pipeline-preview-left">
            <span className="pipeline-preview-num">5</span>
            <span>Canonical RFC 8785 provenance record & server digital signature</span>
          </div>
          <span className="dispatch-algo-tag">ML-DSA-65</span>
        </div>
      </div>
    </div>
  );
}
