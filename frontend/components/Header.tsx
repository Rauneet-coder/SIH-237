"use client";
import { ArrowUpRight, LogOut } from "lucide-react";
import { useAuth } from "../lib/authContext";
export function Header({
  title,
  onSignIn,
}: {
  title: string;
  onSignIn: () => void;
}) {
  const { user, logout } = useAuth();
  return (
    <header className="workspace-header">
      <div className="breadcrumb">
        Workspace <span>/</span> <strong>{title}</strong>
      </div>
      <div className="header-right">
        <span className="project-tag">SIH 26237</span>
        {user ? (
          <>
            <span className="profile-avatar">
              {user.username.slice(0, 2).toUpperCase()}
            </span>
            <span className="profile-name">{user.username}</span>
            <button
              className="icon-button"
              onClick={logout}
              aria-label="Sign out"
            >
              <LogOut size={17} />
            </button>
          </>
        ) : (
          <button className="header-login" onClick={onSignIn}>
            Sign in to workspace <ArrowUpRight size={15} />
          </button>
        )}
      </div>
    </header>
  );
}
