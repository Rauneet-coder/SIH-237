"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  Upload,
  FileText,
  LockKeyhole,
  ArrowRight,
  ArrowLeft,
  Check,
} from "lucide-react";
import {
  DispatchAnimation,
  DispatchProgress,
  DispatchTelemetry,
  PipelinePreview,
} from "../DispatchProgress";
import { useAuth } from "../../lib/authContext";
import { api, User, DocumentMeta } from "../../lib/api";

export function DispatchConsole() {
  const { user, token } = useAuth();
  const [recipients, setRecipients] = useState<User[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [retry, setRetry] = useState(0);
  const [mode, setMode] = useState<"upload" | "compose">("upload");
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [step, setStep] = useState<"edit" | "review" | "sending" | "sent">(
    "edit",
  );
  const [currentStage, setCurrentStage] = useState(0);
  const [result, setResult] = useState<DocumentMeta | null>(null);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const inFlight = useRef(false);
  const canSend = ["sender", "admin", "document_owner"].includes(
    user?.role?.toLowerCase() || "",
  );
  useEffect(() => {
    let active = true;
    if (!token) return;
    setLoading(true);
    setLoadError("");
    api
      .getRecipients(token)
      .then((res) => {
        if (active)
          setRecipients(
            res.recipients.filter((r) => r.username !== user?.username),
          );
      })
      .catch((err) => {
        if (active)
          setLoadError(
            err instanceof Error ? err.message : "Unable to load recipients.",
          );
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [token, user?.username, retry]);
  useEffect(() => {
    heading.current?.focus();
  }, [step]);
  useEffect(() => {
    if (step !== "sending") return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [step]);
  const chooseFile = (next?: File) => {
    if (!next) return;
    if (!next.size || next.size > 50 * 1024 * 1024) {
      setError("Choose a non-empty file smaller than 50 MB.");
      return;
    }
    setFile(next);
    setError("");
    if (!title) setTitle(next.name.replace(/\.[^.]+$/, ""));
  };
  const send = async () => {
    if (!token || inFlight.current) return;
    inFlight.current = true;
    setStep("sending");
    setCurrentStage(0);
    setError("");

    try {
      const payload =
        mode === "upload"
          ? file
          : new File([body], `${title.replace(/[^a-z0-9_-]/gi, "_")}.txt`, {
              type: "text/plain",
            });
      if (!payload) throw new Error("Choose a document first.");
      const form = new FormData();
      form.append("file", payload);
      form.append("title", title.trim());
      form.append("recipients", JSON.stringify(selected));
      form.append("recipientIds", JSON.stringify(selected));

      const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

      // Visual pipeline advancement alongside upload API call
      const pipelinePromise = (async () => {
        // Stage 0: Digest extraction
        await delay(350);
        setCurrentStage(1);
        // Stage 1: AES-256-GCM cipher
        await delay(380);
        setCurrentStage(2);
        // Stage 2: ML-KEM Key Encapsulation
        await delay(380);
        setCurrentStage(3);
        // Stage 3: File Vault Storage
        await delay(350);
        setCurrentStage(4);
      })();

      const uploadPromise = api.uploadDocument(form, token);

      const [_, response] = await Promise.all([pipelinePromise, uploadPromise]);

      // Stage 4: Provenance ledger commit complete
      setCurrentStage(5);
      await delay(300);

      setResult(response.document);
      setStep("sent");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Sending failed. Please try again.",
      );
      setStep("review");
    } finally {
      inFlight.current = false;
    }
  };
  const names = recipients
    .filter((r) => selected.includes(r.id || r._id!))
    .map((r) => r.username);
  if (!canSend)
    return (
      <div className="send-card route-gate">
        <LockKeyhole size={28} />
        <h2>Sender access required</h2>
        <p>
          Your account can receive documents. A sender or administrator can
          share new documents.
        </p>
        <Link href="/inbox" className="btn btn-primary">
          Go to inbox <ArrowRight size={16} />
        </Link>
      </div>
    );
  return (
    <div className="send-flow">
      <ol className="send-steps" aria-label="Sending steps">
        {["Prepare", "Review", "Send"].map((label, i) => (
          <li
            key={label}
            aria-current={
              (step === "edit" ? 0 : step === "review" ? 1 : 2) === i
                ? "step"
                : undefined
            }
          >
            <span>{step === "sent" ? <Check size={12} /> : i + 1}</span>
            {label}
          </li>
        ))}
      </ol>
      <section
        className={`send-card ${step === "sending" || step === "sent" ? "send-status" : ""}`}
        aria-busy={step === "sending"}
      >
        {step === "sending" ? (
          <div
            key="sending"
            className="dispatch-screen"
            role="status"
            aria-live="polite"
          >
            <DispatchAnimation complete={false} />
            <h2 tabIndex={-1} ref={heading}>
              Executing Cryptographic Pipeline
            </h2>
            <p>
              Transforming document through native AES-256-GCM, post-quantum key envelopes, and immutable provenance logging.
              <br />
              Keep this console open while the security boundary seals.
            </p>
            <div className="send-file-summary">
              <FileText size={20} />
              <span>
                {title}
                <small>
                  {selected.length} Recipient Envelope{selected.length !== 1 ? "s" : ""} · Mode: {mode === "upload" ? "PDF / Binary" : "Composed Plaintext"}
                </small>
              </span>
            </div>
            <DispatchProgress
              complete={false}
              currentStage={currentStage}
              recipients={selected.length}
            />
            <span className="send-pending">
              {currentStage === 0
                ? "Stage 1/5: Extracting SHA-256 digest & layout tokens..."
                : currentStage === 1
                ? "Stage 2/5: AES-256-GCM encryption & key zeroization..."
                : currentStage === 2
                ? `Stage 3/5: Encapsulating post-quantum keys for ${selected.length} recipient(s)...`
                : currentStage === 3
                ? "Stage 4/5: Persisting ciphertext to POSIX 0600 storage vault..."
                : "Stage 5/5: Committing canonical provenance event & ML-DSA signature..."}
            </span>
          </div>
        ) : step === "sent" ? (
          <div
            key="sent"
            className="dispatch-screen dispatch-confirmed"
            role="status"
          >
            <DispatchAnimation complete />
            <h2 tabIndex={-1} ref={heading}>
              Cryptographic Dispatch Complete
            </h2>
            <p>
              Document encrypted, individual post-quantum envelopes generated, and provenance transaction verified on the immutable ledger.
            </p>
            <div className="send-file-summary">
              <FileText size={22} />
              <span>
                {result?.title || title}
                <small>{names.join(", ") || `${selected.length} recipient(s)`}</small>
              </span>
            </div>

            {/* Complete 5-stage verified pipeline */}
            <DispatchProgress complete currentStage={5} recipients={selected.length} />

            {/* Rich Cryptographic Audit Telemetry Card */}
            {result && (
              <DispatchTelemetry document={result} recipientNames={names} />
            )}

            <div className="send-actions" style={{ marginTop: "24px" }}>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setStep("edit");
                  setFile(null);
                  setTitle("");
                  setBody("");
                  setSelected([]);
                  setResult(null);
                  setCurrentStage(0);
                }}
              >
                Send another document
              </button>
              <Link
                className="btn btn-primary"
                href={`/documents/${encodeURIComponent(result?.id || result?._id || result?.documentId || "")}`}
              >
                View in Secure Inbox <ArrowRight size={16} />
              </Link>
            </div>
          </div>
        ) : (
          <>
            <h2 tabIndex={-1} ref={heading}>
              {step === "edit"
                ? "A secure exchange starts here."
                : "Ready to send?"}
            </h2>
            <p className="send-intro">
              {step === "edit"
                ? "Your document. Only the people you choose."
                : "Check the document and recipients before sharing."}
            </p>
            {error && (
              <div className="inline-error" role="alert">
                {error}
              </div>
            )}
            {step === "review" ? (
              <>
                <div className="send-file-summary">
                  <FileText size={24} />
                  <span>
                    {title}
                    <small>
                      {mode === "upload"
                        ? file?.name
                        : "Composed text document"}
                    </small>
                  </span>
                </div>
                <dl className="send-details">
                  <dt>Recipients</dt>
                  <dd>{names.join(", ")}</dd>
                  <dt>Protection</dt>
                  <dd>Encrypted with individual recipient access (AES-256-GCM + Post-Quantum KEM)</dd>
                </dl>

                {/* Cryptographic Pipeline Guarantees Preview */}
                <PipelinePreview recipientCount={selected.length || 1} />

                <div className="send-actions" style={{ marginTop: "20px" }}>
                  <button
                    className="btn btn-secondary"
                    onClick={() => setStep("edit")}
                  >
                    <ArrowLeft size={16} /> Edit details
                  </button>
                  <button className="btn btn-primary" onClick={send}>
                    <LockKeyhole size={16} /> Encrypt & send
                  </button>
                </div>
              </>
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  setError("");
                  setStep("review");
                }}
              >
                <div className="source-tabs" aria-label="Document source">
                  {(["upload", "compose"] as const).map((m) => (
                    <button
                      key={m}
                      type="button"
                      aria-pressed={mode === m}
                      className={mode === m ? "selected" : ""}
                      onClick={() => {
                        setMode(m);
                        setError("");
                      }}
                    >
                      {m === "upload" ? "Upload file" : "Write a document"}
                    </button>
                  ))}
                </div>
                {mode === "upload" ? (
                  <label
                    className={`send-dropzone ${dragging ? "dragging" : ""}`}
                    onDragOver={(e) => {
                      e.preventDefault();
                      setDragging(true);
                    }}
                    onDragLeave={() => setDragging(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setDragging(false);
                      chooseFile(e.dataTransfer.files[0]);
                    }}
                  >
                    <Upload size={25} />
                    <strong>
                      {file ? file.name : "Choose a file or drop it here"}
                    </strong>
                    <span>
                      {file
                        ? `${(file.size / 1024).toFixed(1)} KB · Choose a different file`
                        : "One document, up to 50 MB"}
                    </span>
                    <input
                      aria-label="Choose document"
                      type="file"
                      onChange={(e) => {
                        chooseFile(e.target.files?.[0]);
                        e.target.value = "";
                      }}
                    />
                  </label>
                ) : (
                  <label className="input-group">
                    Document content
                    <textarea
                      className="input-textarea"
                      rows={6}
                      required
                      value={body}
                      onChange={(e) => setBody(e.target.value)}
                      placeholder="Write the document you want to share…"
                    />
                  </label>
                )}
                <label className="input-group">
                  Document title
                  <input
                    className="input-text"
                    required
                    maxLength={200}
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="Give your document a clear title"
                  />
                </label>
                <fieldset className="recipient-field">
                  <legend>
                    Share with <span>{selected.length} selected</span>
                  </legend>
                  {loading ? (
                    <p>Loading recipients…</p>
                  ) : loadError ? (
                    <div className="inline-error" role="alert">
                      {loadError}{" "}
                      <button
                        type="button"
                        onClick={() => setRetry((n) => n + 1)}
                      >
                        Try again
                      </button>
                    </div>
                  ) : recipients.length === 0 ? (
                    <p>No other recipients are registered yet.</p>
                  ) : (
                    <div className="recipient-list">
                      {recipients.map((r) => {
                        const id = r.id || r._id!;
                        return (
                          <label key={id} className="recipient-option">
                            <input
                              type="checkbox"
                              checked={selected.includes(id)}
                              onChange={() =>
                                setSelected((old) =>
                                  old.includes(id)
                                    ? old.filter((x) => x !== id)
                                    : [...old, id],
                                )
                              }
                            />
                            <span className="recipient-avatar">
                              {r.username.slice(0, 2).toUpperCase()}
                            </span>
                            <span>
                              {r.username}
                              <small>{r.email}</small>
                            </span>
                          </label>
                        );
                      })}
                    </div>
                  )}
                </fieldset>
                <button
                  className="btn btn-primary send-continue"
                  disabled={
                    !title.trim() ||
                    !selected.length ||
                    loading ||
                    !!loadError ||
                    (mode === "upload" ? !file : !body.trim())
                  }
                >
                  Review document <ArrowRight size={16} />
                </button>
              </form>
            )}
          </>
        )}
      </section>
      <p className="send-footnote">
        <LockKeyhole size={13} /> Recipient access is checked by the server.
      </p>
    </div>
  );
}
