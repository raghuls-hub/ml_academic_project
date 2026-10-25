import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import HostDashboard from './pages/HostDashboard';
import NetworkDashboard from './pages/NetworkDashboard';
import AuthDashboard from './pages/AuthDashboard';
import api from './services/api';
import { Shield, AlertTriangle, Cpu, Terminal, Radio } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('host');
  const [systemHealth, setSystemHealth] = useState(null);
  const [overallThreatLevel, setOverallThreatLevel] = useState('NORMAL');

  // Fetch health status on mount
  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const health = await api.checkHealth();
        setSystemHealth(health);
      } catch (err) {
        console.warn('Backend server not currently responding at /api/v1/health. Running client with fallback presets.');
        setSystemHealth({
          status: 'offline',
          service: 'AI SOC Platform (Client Mode)',
          all_artifacts_present: false,
          llm_engine: {
            model: 'llama-3.3-70b-versatile',
            groq_client_ready: false,
          },
        });
      }
    };
    fetchHealth();
  }, []);

  const handleThreatUpdate = (level) => {
    if (level === 'CRITICAL') {
      setOverallThreatLevel('CRITICAL');
    } else if (level === 'HIGH' && overallThreatLevel !== 'CRITICAL') {
      setOverallThreatLevel('HIGH');
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Background Cyber Grid */}
      <div className="fixed inset-0 cyber-grid opacity-40 pointer-events-none z-0" />

      {/* Navigation Header */}
      <div className="relative z-10">
        <Navbar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          systemHealth={systemHealth}
          overallThreatLevel={overallThreatLevel}
        />
      </div>

      {/* Main Command Center Body */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Active Module Renderer */}
        {activeTab === 'host' && (
          <HostDashboard onThreatUpdate={handleThreatUpdate} />
        )}
        {activeTab === 'network' && (
          <NetworkDashboard onThreatUpdate={handleThreatUpdate} />
        )}
        {activeTab === 'auth' && (
          <AuthDashboard onThreatUpdate={handleThreatUpdate} />
        )}
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-[#090e1c] py-6 px-6 text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-300 font-semibold">AI Cybersecurity Operations Center (SOC)</span>
            <span>—</span>
            <span>Production Tri-Vector ML & LLM Architecture</span>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-400">
            <span>Model: <strong className="text-cyan-300">llama-3.3-70b-versatile</strong></span>
            <span>•</span>
            <span>Host: <strong className="text-slate-200">BETH Kernel Anomaly</strong></span>
            <span>•</span>
            <span>Network: <strong className="text-slate-200">NSL-KDD Random Forest</strong></span>
            <span>•</span>
            <span>Auth: <strong className="text-slate-200">CERT Insider Threat</strong></span>
          </div>
        </div>
      </footer>
    </div>
  );
}

