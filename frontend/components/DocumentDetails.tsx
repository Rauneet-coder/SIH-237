"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  ArrowUpRight,
  Copy,
  FileText,
  ShieldCheck,
  Users,
} from "lucide-react";
import { api, DocumentMeta, ProvenanceLogEntry } from "../lib/api";
import { useAuth } from "../lib/authContext";
import {
  documentId,
  dateLabel,
  fileSize,
  recipientCount,
} from "../lib/documents";
export function DocumentDetails({ id }: { id: string }) {
  const { token } = useAuth();
  const [doc, setDoc] = useState<DocumentMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [logs, setLogs] = useState<ProvenanceLogEntry[]>([]);
  const [logError, setLogError] = useState("");
  const [logLoading, setLogLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [copyStatus, setCopyStatus] = useState("");
  useEffect(() => {
    let active = true;
    if (!token) return;
    setLoading(true);
    setDoc(null);
    setError("");
    api
      .listDocuments(token)
      .then((res) => {
        if (!active) return;
        const found = res.documents.find((d) => documentId(d) === id);
        if (!found)
          throw new Error(
            "This document is unavailable or your account does not have access.",
          );
        setDoc(found);
      })
      .catch((e) => {
        if (active)
          setError(e instanceof Error ? e.message : "Unable to load document.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [token, id, retry]);
  useEffect(() => {
    let active = true;
    if (!token || !doc) return;
    setLogLoading(true);
    setLogError("");
    setLogs([]);
    api
      .listLogs({ docId: id, limit: "10", skip: String(page * 10) }, token)
      .then((res) => {
        if (active) {
          setLogs(res.logs);
          setTotal(res.total);
        }
      })
      .catch((e) => {
        if (active)
          setLogError(
            e instanceof Error ? e.message : "History is unavailable.",
          );
      })
      .finally(() => {
        if (active) setLogLoading(false);
      });
    return () => {
      active = false;
    };
  }, [token, id, doc, page, retry]);
  return (
    <section className="tool-console console-enter">
      <Link href="/inbox" className="detail-back">
        <ArrowLeft size={15} /> All documents
      </Link>
      {loading ? (
        <div className="library-loading" role="status">
          <div className="loading-row" />
          <div className="loading-row" />
          Loading document…
        </div>
      ) : error || !doc ? (
        <div className="inline-error" role="alert">
          {error}
          <button onClick={() => setRetry((n) => n + 1)}>Try again</button>
        </div>
      ) : (
        <>
          <div className="page-heading">
            <div>
              <div className="eyebrow">DOCUMENT RECORD</div>
              <h1>{doc.title}</h1>
              <p>
                {doc.fileName} · {fileSize(doc.fileSize)}
              </p>
            </div>
            <Link
              href={`/documents/${encodeURIComponent(id)}/view`}
              className="btn btn-primary"
            >
              Open secure viewer <ArrowUpRight size={16} />
            </Link>
          </div>
          <div className="detail-grid">
            <section className="detail-card">
              <h2>
                <FileText size={18} /> Document details
              </h2>
              <dl className="record-details">
                <dt>Sender</dt>
                <dd>{doc.senderId?.username || "Unavailable"}</dd>
                <dt>Created</dt>
                <dd>{dateLabel(doc.createdAt)}</dd>
                <dt>File type</dt>
                <dd>{doc.mimeType || "Unavailable"}</dd>
                <dt>Classification</dt>
                <dd>{doc.classification || "Not provided"}</dd>
                <dt>Document ID</dt>
                <dd className="record-id">
                  {id}
                  <button
                    className="icon-button"
                    aria-label="Copy document ID"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(id);
                        setCopyStatus("Document ID copied.");
                      } catch {
                        setCopyStatus(
                          "Copy unavailable. Select the document ID to copy it.",
                        );
                      }
                    }}
                  >
                    <Copy size={14} />
                  </button>
                </dd>
              </dl>
              <p role="status" className="copy-status">
                {copyStatus}
              </p>
              <details className="record-technical">
                <summary>Integrity fingerprint</summary>
                <p>Stored SHA-256 document hash</p>
                <code>{doc.fileHash || "Unavailable"}</code>
              </details>
            </section>
            <section className="detail-card">
              <h2>
                <Users size={18} /> Recipient access{" "}
                <span className="badge">{recipientCount(doc)}</span>
              </h2>
              <p className="detail-caption">
                Opening the viewer checks your current access on the server.
              </p>
              {doc.recipientKeys?.length ? (
                <ul className="detail-recipients">
                  {doc.recipientKeys.map((r, i) => (
                    <li key={i}>
                      <span className="recipient-avatar">
                        {r.recipientId?.username?.slice(0, 2).toUpperCase() ||
                          "ID"}
                      </span>
                      <span>
                        {r.recipientId?.username || "Registered recipient"}
                        <small>
                          {r.recipientId?.email ||
                            "Identity details unavailable"}
                        </small>
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="empty-state">
                  {recipientCount(doc)} recipient
                  {recipientCount(doc) === 1 ? "" : "s"} assigned. Names are not
                  included in this document record.
                </p>
              )}
              {doc.recipientKeys?.length > 0 && doc.recipientKeys.length < recipientCount(doc) && <p className="detail-caption">{doc.recipientKeys.length} of {recipientCount(doc)} recipient identities are included in this record.</p>}
            <Link href="/keys" className="text-button">
                Manage access keys <ArrowUpRight size={14} />
              </Link>
            </section>
          </div>
          <section className="detail-card detail-history">
            <div className="section-title">
              <h2>
                <ShieldCheck size={18} /> Document activity
              </h2>
              <Link href="/ledger" className="text-button">
                Verify ledger <ArrowUpRight size={14} />
              </Link>
            </div>
            <p className="detail-caption">
              Recorded events in chronological order. Verification is available
              in the activity ledger.
            </p>
            {logError ? (
              <div className="inline-error" role="alert">
                History unavailable: {logError}{" "}
                <button onClick={() => setRetry((n) => n + 1)}>
                  Try again
                </button>
              </div>
            ) : logLoading ? (
              <p role="status" className="empty-state">
                Loading activity…
              </p>
            ) : !logs.length ? (
              <p className="empty-state">
                No activity records returned for this document.
              </p>
            ) : (
              <>
                <ol className="record-timeline">
                  {logs.map((l) => (
                    <li key={l._id}>
                      <span
                        className={`badge ${l.status === "SUCCESS" ? "badge-success" : "badge-danger"}`}
                      >
                        {l.status === "SUCCESS" ? "Success" : "Failed"}
                      </span>
                      <div>
                        <strong>
                          {["ENCRYPT_UPLOAD", "DOCUMENT_UPLOAD"].includes(l.action)
                            ? "Document uploaded"
                            : l.action === "DECRYPT_SUCCESS"
                              ? "Document decrypted"
                              : l.action === "DECRYPT_FAILURE"
                                ? "Decryption attempt failed"
                                : String(l.action).replaceAll("_", " ").toLowerCase()}
                        </strong>
                        <p>
                          {l.recipientId?.username || "Unavailable identity"} ·{" "}
                          {dateLabel(l.timestamp)}
                        </p>
                        {l.failureReason && <p>{l.failureReason}</p>}
                      </div>
                      <span className="text-muted">#{l.sequenceNumber}</span>
                    </li>
                  ))}
                </ol>
                <div className="library-pagination">
                  <span>
                    {page * 10 + 1}–{Math.min(page * 10 + 10, total)} of {total}{" "}
                    events
                  </span>
                  <div>
                    <button
                      className="btn btn-secondary"
                      disabled={!page}
                      onClick={() => setPage((n) => n - 1)}
                    >
                      Previous
                    </button>
                    <button
                      className="btn btn-secondary"
                      disabled={(page + 1) * 10 >= total}
                      onClick={() => setPage((n) => n + 1)}
                    >
                      Next
                    </button>
                  </div>
                </div>
              </>
            )}
          </section>
        </>
      )}
    </section>
  );
}
