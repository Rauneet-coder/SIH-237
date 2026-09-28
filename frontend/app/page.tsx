"use client";
import { useEffect, useRef, useState } from "react";
import { ArrowUpRight, Download, X } from "lucide-react";
import { AuthProvider, useAuth, COMMAND_OFFICERS } from "../lib/authContext";
import { Header } from "../components/Header";
import { ConsoleNav, ConsoleTab, consoleTabs } from "../components/ConsoleNav";
import { OverviewConsole } from "../components/consoles/OverviewConsole";
import { DispatchConsole } from "../components/consoles/DispatchConsole";
import { InboxConsole } from "../components/consoles/InboxConsole";
import { ForensicsConsole } from "../components/consoles/ForensicsConsole";
import { LedgerConsole } from "../components/consoles/LedgerConsole";
import { KeyVaultConsole } from "../components/consoles/KeyVaultConsole";
function Workspace() {
  const { user, login, register, quickSwitchUser, isLoading } = useAuth();
  const [tab, setTab] = useState<ConsoleTab>("overview");
  const [pending, setPending] = useState<ConsoleTab>("overview");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [key, setKey] = useState("");
  const [keyName, setKeyName] = useState("");
  const dialog = useRef<HTMLDialogElement>(null);
  const keyDialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (!user) setTab("overview");
  }, [user]);
  useEffect(() => {
    if (key) keyDialog.current?.showModal();
  }, [key]);
  const openAuth = () => {
    setError("");
    dialog.current?.showModal();
  };
  const navigate = (next: ConsoleTab) => {
    if (!user && next !== "overview") {
      setPending(next);
      openAuth();
    } else setTab(next);
  };
  const finish = () => {
    dialog.current?.close();
    setTab(pending);
  };
  const submit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const d = new FormData(e.currentTarget);
    const username = String(d.get("username"));
    const password = String(d.get("password"));
    try {
      if (mode === "register") {
        const regKey = await register(
          username,
          String(d.get("email")),
          password,
          String(d.get("role")),
        );
        if (regKey) setKey(regKey);
        setKeyName(username);
      }
      await login(username, password);
      finish();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to sign in.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="app-shell">
      <ConsoleNav activeTab={tab} onTabChange={navigate} />
      <div className="workspace-main">
        <Header
          title={consoleTabs.find((t) => t.id === tab)?.label || "Overview"}
          onSignIn={openAuth}
        />
        <main className="main-content">
          {tab === "overview" ? (
            <OverviewConsole onNavigate={navigate} />
          ) : (
            <div className="tool-console console-enter">
              <div className="tool-heading">
                <div className="eyebrow">PRAMAAN / WORKSPACE</div>
                <h1>{consoleTabs.find((t) => t.id === tab)?.label}</h1>
                <p>Every exchange has a story. Keep the record complete.</p>
              </div>
              {tab === "dispatch" && <DispatchConsole onSuccess={() => {}} />}
              {tab === "inbox" && <InboxConsole />}
              {tab === "forensics" && <ForensicsConsole />}
              {tab === "ledger" && <LedgerConsole />}
              {tab === "vault" && <KeyVaultConsole />}
            </div>
          )}
        </main>
      </div>
      <dialog ref={dialog} className="auth-dialog" aria-labelledby="auth-title">
        <button
          className="dialog-close icon-button"
          onClick={() => dialog.current?.close()}
          aria-label="Close sign in"
        >
          <X size={20} />
        </button>
        <div className="eyebrow">YOUR SECURE WORKSPACE</div>
        <h2 id="auth-title">
          {mode === "login" ? "Welcome back." : "Make it official."}
        </h2>
        <p>
          {mode === "login"
            ? "Sign in to start your next secure exchange."
            : "Create your identity and recipient key pair."}
        </p>
        <div className="auth-tabs">
          {(["login", "register"] as const).map((m) => (
            <button
              key={m}
              className={mode === m ? "selected" : ""}
              onClick={() => {
                setMode(m);
                setError("");
              }}
            >
              {m === "login" ? "Sign in" : "Create account"}
            </button>
          ))}
        </div>
        {error && (
          <div className="inline-error" role="alert">
            {error}
          </div>
        )}
        <form onSubmit={submit}>
          <label className="input-group">
            Username
            <input
              className="input-text"
              name="username"
              autoComplete="username"
              required
              placeholder="Your username"
            />
          </label>
          {mode === "register" && (
            <>
              <label className="input-group">
                Email
                <input
                  className="input-text"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                />
              </label>
              <label className="input-group">
                Workspace role
                <select className="input-select" name="role">
                  <option value="recipient">Recipient</option>
                  <option value="sender">Sender</option>
                  <option value="investigator">Investigator</option>
                  <option value="admin">Auditor</option>
                </select>
              </label>
            </>
          )}
          <label className="input-group">
            Password
            <input
              className="input-text"
              name="password"
              type="password"
              autoComplete={
                mode === "login" ? "current-password" : "new-password"
              }
              required
            />
          </label>
          <button
            className="btn btn-primary auth-submit"
            disabled={busy || isLoading}
          >
            {busy
              ? "Connecting…"
              : mode === "login"
                ? "Enter workspace"
                : "Create account"}
            <ArrowUpRight size={16} />
          </button>
        </form>
        <details className="demo-accounts">
          <summary>Try a demonstration account</summary>
          <p>
            Uses the connected demo server. Accounts may be created on first
            use.
          </p>
          {COMMAND_OFFICERS.map((p) => (
            <button
              key={p.username}
              disabled={busy || isLoading}
              onClick={async () => {
                setBusy(true);
                setError("");
                try {
                  await quickSwitchUser(p);
                  finish();
                } catch (e) {
                  setError(
                    e instanceof Error ? e.message : "Demo server unavailable.",
                  );
                } finally {
                  setBusy(false);
                }
              }}
            >
              <span>
                {p.name}
                <small>{p.role}</small>
              </span>
              <ArrowUpRight size={14} />
            </button>
          ))}
        </details>
      </dialog>
      <dialog
        ref={keyDialog}
        className="auth-dialog"
        aria-labelledby="key-title"
        onClose={() => setKey("")}
      >
        <h2 id="key-title">Your private key.</h2>
        <p>
          Save this file to access documents shared with you. Keep it private
          and store it somewhere safe.
        </p>
        <button
          className="btn btn-primary auth-submit"
          onClick={() => {
            const url = URL.createObjectURL(
              new Blob([key], { type: "application/x-pem-file" }),
            );
            const a = document.createElement("a");
            a.href = url;
            a.download = `${keyName}_private_key.pem`;
            a.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
          }}
        >
          <Download size={16} />
          Download private key
        </button>
        <button
          className="btn btn-secondary auth-submit"
          onClick={() => keyDialog.current?.close()}
        >
          Continue to workspace
        </button>
      </dialog>
    </div>
  );
}
export default function Home() {
  return (
    <AuthProvider>
      <Workspace />
    </AuthProvider>
  );
}
