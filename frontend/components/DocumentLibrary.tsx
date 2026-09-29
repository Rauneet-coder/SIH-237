"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, FileText, Search, RefreshCw, Inbox } from "lucide-react";
import { api, DocumentMeta } from "../lib/api";
import { useAuth } from "../lib/authContext";
import {
  documentId,
  isSent,
  isReceived,
  recipientCount,
  fileSize,
  dateLabel,
} from "../lib/documents";
export function DocumentLibrary() {
  const { token, user } = useAuth();
  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState("all");
  const [sort, setSort] = useState("newest");
  const [page, setPage] = useState(0);
  useEffect(() => {
    let active = true;
    if (!token) return;
    setLoading(true);
    setError("");
    setDocuments([]);
    api
      .listDocuments(token)
      .then((res) => {
        if (active) setDocuments(res.documents);
      })
      .catch((e) => {
        if (active)
          setError(
            e instanceof Error ? e.message : "Unable to load documents.",
          );
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [token, refresh]);
  const filtered = useMemo(
    () =>
      documents
        .filter(
          (d) =>
            (scope === "sent"
              ? isSent(d, user)
              : scope === "received"
                ? isReceived(d, user)
                : true) &&
            `${d.title} ${d.fileName} ${d.senderId?.username || ""}`
              .toLowerCase()
              .includes(query.trim().toLowerCase()),
        )
        .sort((a, b) =>
          sort === "name"
            ? a.title.localeCompare(b.title)
            : sort === "oldest"
              ? Date.parse(a.createdAt) - Date.parse(b.createdAt)
              : Date.parse(b.createdAt) - Date.parse(a.createdAt),
        ),
    [documents, scope, query, sort, user],
  );
  useEffect(() => setPage(0), [query, scope, sort, refresh]);
  return (
    <section className="tool-console console-enter">
      <div className="page-heading">
        <div>
          <h1>Document workspace</h1>
          <p>Find a document, review its record, and open it securely.</p>
        </div>
        <Link className="btn btn-primary" href="/send">
          Send document <ArrowUpRight size={16} />
        </Link>
      </div>
      <div className="library-toolbar">
        <div className="library-tabs" aria-label="Document filter">
          {[
            ["all", "All documents"],
            ["received", "Received"],
            ["sent", "Sent by me"],
          ].map(([value, label]) => (
            <button
              key={value}
              onClick={() => setScope(value)}
              aria-pressed={scope === value}
            >
              {label}
              <span>
                {
                  documents.filter((d) =>
                    value === "sent"
                      ? isSent(d, user)
                      : value === "received"
                        ? isReceived(d, user)
                        : true,
                  ).length
                }
              </span>
            </button>
          ))}
        </div>
        <button
          className="icon-button"
          aria-label="Refresh documents"
          disabled={loading}
          onClick={() => setRefresh((n) => n + 1)}
        >
          <RefreshCw size={16} className={loading ? "spin" : ""} />
        </button>
      </div>
      <div className="library-controls">
        <label className="library-search">
          <Search size={17} />
          <input
            aria-label="Search documents"
            placeholder="Search title, file name, or sender"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <label className="library-sort">
          Sort by
          <select value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
            <option value="name">Document name</option>
          </select>
        </label>
      </div>
      {error ? (
        <div className="inline-error" role="alert">
          {error}{" "}
          <button onClick={() => setRefresh((n) => n + 1)}>Try again</button>
        </div>
      ) : loading ? (
        <div
          className="library-loading"
          role="status"
          aria-label="Loading documents"
        >
          {[1, 2, 3, 4].map((i) => (
            <div className="loading-row" key={i} />
          ))}
          <span>Loading documents…</span>
        </div>
      ) : !filtered.length ? (
        <div className="library-empty">
          <Inbox size={30} />
          <h2>
            {query || scope !== "all"
              ? "No matching documents"
              : "Your documents will appear here"}
          </h2>
          <p>
            {query || scope !== "all"
              ? "Try a different search or reset your filters."
              : "Documents you send or receive will be listed in this workspace."}
          </p>
          {query || scope !== "all" ? (
            <button
              className="btn btn-secondary"
              onClick={() => {
                setQuery("");
                setScope("all");
              }}
            >
              Reset filters
            </button>
          ) : (
            <Link className="btn btn-primary" href="/send">
              Send a document
            </Link>
          )}
        </div>
      ) : (
        <>
          <div className="library-table-wrap">
            <table className="library-table">
              <thead>
                <tr>
                  <th>Document</th>
                  <th>Sender</th>
                  <th>Recipients</th>
                  <th>Created</th>
                  <th>
                    <span className="sr-only">Action</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(page * 10, page * 10 + 10).map((d) => (
                  <tr key={documentId(d)}>
                    <td>
                      <Link
                        className="library-document"
                        href={`/documents/${encodeURIComponent(documentId(d))}`}
                      >
                        <span className="file-icon">
                          <FileText size={19} />
                        </span>
                        <span>
                          <strong>{d.title}</strong>
                          <small>
                            {d.fileName} · {fileSize(d.fileSize)}
                          </small>
                        </span>
                      </Link>
                    </td>
                    <td>
                      {d.senderId?.username || "Unavailable"}
                      {isSent(d, user) && <small>You</small>}
                    </td>
                    <td>{recipientCount(d)}</td>
                    <td>{dateLabel(d.createdAt)}</td>
                    <td>
                      <Link
                        className="icon-button"
                        href={`/documents/${encodeURIComponent(documentId(d))}`}
                        aria-label={`View details for ${d.title}`}
                      >
                        <ArrowUpRight size={17} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="library-pagination">
            <span>
              {page * 10 + 1}–{Math.min(page * 10 + 10, filtered.length)} of{" "}
              {filtered.length} documents
            </span>
            <div>
              <button
                className="btn btn-secondary"
                disabled={page === 0}
                onClick={() => setPage((n) => n - 1)}
              >
                Previous
              </button>
              <button
                className="btn btn-secondary"
                disabled={(page + 1) * 10 >= filtered.length}
                onClick={() => setPage((n) => n + 1)}
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
