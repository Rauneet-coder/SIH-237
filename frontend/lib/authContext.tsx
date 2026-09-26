'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { api, User } from './api';
import { DEMO_PRIVATE_KEYS } from './demoKeys';

interface AuthContextType {
  user: User | null;
  token: string | null;
  cachedPrivateKey: string | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string, role?: string) => Promise<string>;
  logout: () => void;
  setCachedPrivateKey: (key: string | null) => void;
  quickSwitchUser: (profile: DemoProfile) => Promise<void>;
}

export interface CommandOfficer {
  name: string;
  username: string;
  email: string;
  role: 'sender' | 'recipient' | 'investigator' | 'admin';
  description: string;
}

export type DemoProfile = CommandOfficer;

export const COMMAND_OFFICERS: CommandOfficer[] = [
  {
    name: 'Col. Sharma',
    username: 'col_sharma',
    email: 'col.sharma@mod.gov.in',
    role: 'sender',
    description: 'Defence HQ Command Dispatcher (Sender)'
  },
  {
    name: 'Maj. Gupta',
    username: 'maj_gupta',
    email: 'maj.gupta@mod.gov.in',
    role: 'recipient',
    description: 'Northern Command Authorized Recipient'
  },
  {
    name: 'Capt. Verma',
    username: 'capt_verma',
    email: 'capt.verma@mod.gov.in',
    role: 'recipient',
    description: 'Eastern Command Authorized Recipient'
  },
  {
    name: 'Special Agent Roy',
    username: 'agent_roy',
    email: 'agent.roy@dia.gov.in',
    role: 'investigator',
    description: 'Defence Intelligence Agency (DIA) Forensic Officer'
  },
  {
    name: 'Auditor General Sen',
    username: 'auditor_sen',
    email: 'auditor.sen@mod.gov.in',
    role: 'admin',
    description: 'Provenance Ledger Cryptographic Inspector'
  }
];

export const DEMO_PROFILES = COMMAND_OFFICERS;

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [cachedPrivateKey, setCachedPrivateKey] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    // Restore session from localStorage if available
    try {
      const storedToken = localStorage.getItem('sih_auth_token');
      const storedUser = localStorage.getItem('sih_auth_user');
      const storedKey = sessionStorage.getItem('sih_private_key');

      if (storedToken && storedUser) {
        setToken(storedToken);
        const parsed = JSON.parse(storedUser);
        setUser(parsed);

        // Always resolve the key specific to the restored user
        const userSpecificKey =
          (parsed.username && DEMO_PRIVATE_KEYS[parsed.username]) ||
          localStorage.getItem(`sih_key_${parsed.username}`) ||
          sessionStorage.getItem(`sih_private_key_${parsed.username}`) ||
          storedKey;
        if (userSpecificKey) {
          setCachedPrivateKey(userSpecificKey);
        }
      }
    } catch (e) {
      console.error('Failed to restore session:', e);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleSetCachedPrivateKey = (key: string | null, activeUsername?: string) => {
    setCachedPrivateKey(key);
    const uname = activeUsername || user?.username;
    if (key) {
      sessionStorage.setItem('sih_private_key', key);
      if (uname) {
        sessionStorage.setItem(`sih_private_key_${uname}`, key);
      }
    } else {
      sessionStorage.removeItem('sih_private_key');
      if (uname) {
        sessionStorage.removeItem(`sih_private_key_${uname}`);
      }
    }
  };

  const login = async (username: string, password: string) => {
    setIsLoading(true);
    try {
      const res = await api.login({ username, password });
      setToken(res.token);
      setUser(res.user);
      localStorage.setItem('sih_auth_token', res.token);
      localStorage.setItem('sih_auth_user', JSON.stringify(res.user));

      // Auto-load private key from demo keys or local vault
      if (DEMO_PRIVATE_KEYS && DEMO_PRIVATE_KEYS[res.user.username]) {
        handleSetCachedPrivateKey(DEMO_PRIVATE_KEYS[res.user.username], res.user.username);
      } else {
        const storedKey = localStorage.getItem(`sih_key_${res.user.username}`);
        handleSetCachedPrivateKey(storedKey || null, res.user.username);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (username: string, email: string, password: string, role = 'recipient') => {
    setIsLoading(true);
    try {
      const res = await api.register({ username, email, password, role });
      if (res.privateKey) {
        localStorage.setItem(`sih_key_${username}`, res.privateKey);
        handleSetCachedPrivateKey(res.privateKey, username);
      }
      return res.privateKey;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    setCachedPrivateKey(null);
    localStorage.removeItem('sih_auth_token');
    localStorage.removeItem('sih_auth_user');
    sessionStorage.removeItem('sih_private_key');
  };

  const quickSwitchUser = async (profile: DemoProfile) => {
    setIsLoading(true);
    const password = 'Password@123';
    try {
      // Try login first
      const res = await api.login({ username: profile.username, password });
      setToken(res.token);
      setUser(res.user);
      localStorage.setItem('sih_auth_token', res.token);
      localStorage.setItem('sih_auth_user', JSON.stringify(res.user));

      // Load matching RSA private key
      if (DEMO_PRIVATE_KEYS && DEMO_PRIVATE_KEYS[profile.username]) {
        handleSetCachedPrivateKey(DEMO_PRIVATE_KEYS[profile.username], profile.username);
      } else {
        const userKey = localStorage.getItem(`sih_key_${profile.username}`);
        handleSetCachedPrivateKey(userKey || null, profile.username);
      }
    } catch {
      // If user doesn't exist, auto-register
      try {
        const regRes = await api.register({
          username: profile.username,
          email: profile.email,
          password,
          role: profile.role
        });
        if (regRes.privateKey) {
          localStorage.setItem(`sih_key_${profile.username}`, regRes.privateKey);
          handleSetCachedPrivateKey(regRes.privateKey);
        }
        // Then login
        const loginRes = await api.login({ username: profile.username, password });
        setToken(loginRes.token);
        setUser(loginRes.user);
        localStorage.setItem('sih_auth_token', loginRes.token);
        localStorage.setItem('sih_auth_user', JSON.stringify(loginRes.user));
      } catch (err: any) {
        console.error('Quick switch failed:', err);
        throw err;
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        cachedPrivateKey,
        isLoading,
        login,
        register,
        logout,
        setCachedPrivateKey: handleSetCachedPrivateKey,
        quickSwitchUser
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
