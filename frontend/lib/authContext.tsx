'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { api, User } from './api';

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

export interface DemoProfile {
  name: string;
  username: string;
  email: string;
  role: 'sender' | 'recipient' | 'investigator' | 'admin';
  description: string;
}

export const DEMO_PROFILES: DemoProfile[] = [
  {
    name: 'Col. Sharma',
    username: 'col_sharma',
    email: 'col.sharma@mod.gov.in',
    role: 'sender',
    description: 'Defence HQ Sender / Document Encryptor'
  },
  {
    name: 'Maj. Gupta',
    username: 'maj_gupta',
    email: 'maj.gupta@mod.gov.in',
    role: 'recipient',
    description: 'Northern Command Recipient'
  },
  {
    name: 'Capt. Verma',
    username: 'capt_verma',
    email: 'capt.verma@mod.gov.in',
    role: 'recipient',
    description: 'Eastern Command Recipient'
  },
  {
    name: 'Special Agent Roy',
    username: 'agent_roy',
    email: 'agent.roy@dia.gov.in',
    role: 'investigator',
    description: 'Forensic Traitor Tracing Officer'
  },
  {
    name: 'Auditor General Sen',
    username: 'auditor_sen',
    email: 'auditor.sen@mod.gov.in',
    role: 'admin',
    description: 'Cryptographic Ledger Inspector'
  }
];

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
        setUser(JSON.parse(storedUser));
      }
      if (storedKey) {
        setCachedPrivateKey(storedKey);
      }
    } catch (e) {
      console.error('Failed to restore session:', e);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const login = async (username: string, password: string) => {
    setIsLoading(true);
    try {
      const res = await api.login({ username, password });
      setToken(res.token);
      setUser(res.user);
      localStorage.setItem('sih_auth_token', res.token);
      localStorage.setItem('sih_auth_user', JSON.stringify(res.user));
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (username: string, email: string, password: string, role = 'recipient') => {
    setIsLoading(true);
    try {
      const res = await api.register({ username, email, password, role });
      setToken(null);
      // Cache generated private key in sessionStorage for convenience
      if (res.privateKey) {
        setCachedPrivateKey(res.privateKey);
        sessionStorage.setItem('sih_private_key', res.privateKey);
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

  const handleSetCachedPrivateKey = (key: string | null) => {
    setCachedPrivateKey(key);
    if (key) {
      sessionStorage.setItem('sih_private_key', key);
    } else {
      sessionStorage.removeItem('sih_private_key');
    }
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

      // Check if we have a stored private key for this user
      const userKey = localStorage.getItem(`sih_key_${profile.username}`);
      if (userKey) {
        handleSetCachedPrivateKey(userKey);
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
