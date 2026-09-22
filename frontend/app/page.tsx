'use client';

import React, { useState } from 'react';
import { AuthProvider } from '../lib/authContext';
import { Header } from '../components/Header';
import { ConsoleNav, ConsoleTab } from '../components/ConsoleNav';

export default function Home() {
  const [activeTab, setActiveTab] = useState<ConsoleTab>('overview');

  return (
    <AuthProvider>
      <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
        <Header chainHeight={0} isChainValid={true} />
        <ConsoleNav activeTab={activeTab} onTabChange={setActiveTab} />
        
        <main className="container-full" style={{ padding: '24px', flex: 1 }}>
          <div className="card" style={{ maxWidth: '600px', margin: '40px auto', textAlign: 'center' }}>
            <span className="badge badge-white font-mono" style={{ marginBottom: '12px' }}>
              SYSTEM BOOT SEQUENCE // ACTIVE
            </span>
            <h1 className="text-xl font-bold" style={{ marginBottom: '8px' }}>
              Cryptographic Attribution Console
            </h1>
            <p className="text-secondary text-sm">
              Initializing defence-grade cryptographic modules and operational consoles...
            </p>
          </div>
        </main>
      </div>
    </AuthProvider>
  );
}
