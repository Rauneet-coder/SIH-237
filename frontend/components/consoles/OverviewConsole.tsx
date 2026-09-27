"use client";
import { useEffect, useState } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  FileText,
  LockKeyhole,
  Layers3,
  ShieldCheck,
  RefreshCw,
} from "lucide-react";
import { useAuth } from "../../lib/authContext";
import {
  api,
  DocumentMeta,
  ProvenanceLogEntry,
  VerificationReport,
} from "../../lib/api";
import { ConsoleTab } from "../ConsoleNav";

export function OverviewConsole({
  onNavigate,
}: {
  onNavigate: (tab: ConsoleTab) => void;
}) {
  const { token } = useAuth();
  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [logs, setLogs] = useState<ProvenanceLogEntry[]>([]);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const load = async () => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const [d, l, v] = await Promise.all([
        api.listDocuments(token),
        api.listLogs({ limit: "4" }, token),
        api.verifyChain(),
      ]);
      setDocuments(d.documents);
      setLogs(l.logs);
      setReport(v.report);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Workspace data is unavailable.",
      );
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    void load();
  }, [token]);
  const preview = !token;
  const rows = preview
    ? [
        {
          id: "01",
          title: "Northern command briefing",
          file: "operational-brief.pdf",
          date: "24 Sep 2026",
          recipients: 3,
        },
        {
          id: "02",
          title: "Infrastructure assessment",
          file: "assessment-report.pdf",
          date: "24 Sep 2026",
          recipients: 5,
        },
        {
          id: "03",
          title: "Quarterly intelligence summary",
          file: "intelligence-q3.pdf",
          date: "23 Sep 2026",
          recipients: 2,
        },
      ]
    : documents.map((d) => ({
        id: d._id,
        title: d.title,
        file: d.fileName,
        date: new Date(d.createdAt).toLocaleDateString("en-GB"),
        recipients: d.recipientCount ?? d.recipientKeys?.length ?? 0,
      }));
  return (
    <div className="overview console-enter">
      <div className="page-heading">
        <div>
          <h1>Your workspace</h1>
          <p>Share documents securely and keep track of every access.</p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => onNavigate("dispatch")}
        >
          <ArrowUpRight size={16} /> Send a document
        </button>
      </div>
      <section className="getting-started" aria-labelledby="sharing-title">
        <div className="sharing-icon">
          <LockKeyhole size={23} strokeWidth={1.5} />
        </div>
        <div className="sharing-copy">
          <h2 id="sharing-title">Secure sharing, made simple</h2>
          <p>
            Choose a file and its recipients. We’ll encrypt it and record access
            in your ledger.
          </p>
        </div>
        <button className="text-button" onClick={() => onNavigate("inbox")}>
          Open inbox <ArrowRight size={15} />
        </button>
      </section>
      <div className="section-meta">
        <span>{preview ? "Preview" : "At a glance"}</span>
        <span>
          {preview
            ? "Sample data · Sign in to see your documents"
            : loading
              ? "Updating workspace…"
              : "Your accessible documents and audit history"}
          {!preview && (
            <button
              className="icon-button"
              aria-label="Refresh workspace"
              onClick={load}
              disabled={loading}
            >
              <RefreshCw size={14} className={loading ? "spin" : ""} />
            </button>
          )}
        </span>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          Unable to load workspace: {error}{" "}
          <button onClick={load}>Try again</button>
        </div>
      )}
      <section className="metrics" aria-label="Workspace statistics">
        {[
          {
            name: "Encrypted documents",
            value: preview
              ? "24"
              : loading || error
                ? "—"
                : String(documents.length).padStart(2, "0"),
            note: "Protected at every exchange",
            icon: FileText,
          },
          {
            name: "Provenance records",
            value: preview ? "128" : report ? String(report.totalBlocks) : "—",
            note: "Every action, accounted for",
            icon: Layers3,
          },
          {
            name: "Chain integrity",
            value: preview
              ? "Verified"
              : report
                ? report.valid
                  ? "Verified"
                  : "Review needed"
                : "Unverified",
            note: preview
              ? "Example verification result"
              : report
                ? "Latest verification result"
                : "Verification required",
            icon: ShieldCheck,
          },
        ].map(({ name, value, note, icon: Icon }, i) => (
          <div className="metric" key={name}>
            <div className="metric-label">
              {name}
              <Icon size={17} strokeWidth={1.5} />
            </div>
            <div className={`metric-value ${i === 2 ? "integrity-value" : ""}`}>
              {i === 2 && (
                <span
                  className={`status-dot ${preview || report?.valid ? "status-dot-green" : "status-dot-amber"}`}
                />
              )}
              {value}
            </div>
            <span className="metric-note">{note}</span>
          </div>
        ))}
      </section>
      <div className="records-grid">
        <section className="documents-panel">
          <div className="section-title">
            <h2>
              Recent documents{" "}
              <span>{rows.length.toString().padStart(2, "0")}</span>
            </h2>
            <button className="text-button" onClick={() => onNavigate("inbox")}>
              View all <ArrowUpRight size={15} />
            </button>
          </div>
          <label className="search-field">
            <span>Find a document</span>
            <input
              aria-label="Search recent documents"
              placeholder="Search by name…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          <div className="document-table">
            <div className="document-table-head">
              <span>DOCUMENT NAME</span>
              <span>RECIPIENTS</span>
              <span>CREATED</span>
              <span />
            </div>
            {rows
              .filter((d) =>
                `${d.title} ${d.file}`
                  .toLowerCase()
                  .includes(query.toLowerCase()),
              )
              .map((d) => (
                <button
                  className="document-row"
                  key={d.id}
                  onClick={() => onNavigate("inbox")}
                >
                  <span className="document-name">
                    <span className="file-icon">
                      <FileText size={19} strokeWidth={1.4} />
                    </span>
                    <span>
                      <strong>{d.title}</strong>
                      <small>{d.file}</small>
                    </span>
                  </span>
                  <span className="recipient-count">
                    {d.recipients} recipients
                  </span>
                  <span className="document-date">{d.date}</span>
                  <ArrowUpRight size={15} />
                </button>
              ))}
            {!rows.filter((d) =>
              `${d.title} ${d.file}`
                .toLowerCase()
                .includes(query.toLowerCase()),
            ).length && (
              <div className="empty-state">
                {query
                  ? "No matching documents."
                  : loading
                    ? "Loading documents…"
                    : "Your first secure exchange starts here."}
              </div>
            )}
          </div>
        </section>
        <section className="activity-panel">
          <div className="section-title">
            <h2>Recent activity</h2>
            <span className="activity-mark">↗</span>
          </div>
          <div className="activity-list">
            {preview ? (
              [
                ["Document decrypted", "Northern command briefing", "14:42"],
                ["Document dispatched", "Infrastructure assessment", "13:18"],
                [
                  "Access attributed",
                  "Quarterly intelligence summary",
                  "11:06",
                ],
              ].map(([title, detail, time], i) => (
                <div className="activity-item" key={title}>
                  <span className={`activity-dot dot-${i}`} />
                  <div>
                    <strong>{title}</strong>
                    <p>{detail}</p>
                    <small>24 SEP · {time}</small>
                  </div>
                </div>
              ))
            ) : logs.length ? (
              logs.map((l) => (
                <div className="activity-item" key={l._id}>
                  <span className="activity-dot" />
                  <div>
                    <strong>
                      {l.action === "ENCRYPT_UPLOAD"
                        ? "Document dispatched"
                        : l.action === "DECRYPT_SUCCESS"
                          ? "Document decrypted"
                          : "Decryption failed"}
                    </strong>
                    <p>{l.docId?.title || "Document record"}</p>
                    <small>{new Date(l.timestamp).toLocaleString()}</small>
                  </div>
                </div>
              ))
            ) : (
              <div className="empty-state">
                {loading
                  ? "Loading activity…"
                  : "Recorded actions will appear here."}
              </div>
            )}
          </div>
          <button className="trail-link" onClick={() => onNavigate("ledger")}>
            View activity history <ArrowRight size={15} />
          </button>
        </section>
      </div>
      <div className="overview-footer">
        <span>
          <LockKeyhole size={12} /> Private documents. Accountable access.
        </span>
        <span>Pramaan · SIH 2026</span>
      </div>
    </div>
  );
}
