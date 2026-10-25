import React, { useState, useEffect } from 'react';
import { Shield, Cpu, Activity, Clock, Terminal, Zap, CheckCircle2, AlertTriangle, Radio } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, systemHealth, overallThreatLevel = 'NORMAL' }) {
  const [currentTime, setCurrentTime] = useState(new Date().toUTCString().slice(17, 25) + ' UTC');

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toUTCString().slice(17, 25) + ' UTC');
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const tabs = [
    { id: 'host', label: 'Host Syscall & Payload', icon: Terminal, module: 'BETH' },
    { id: 'network', label: 'Network Intrusion Inspector', icon: Activity, module: 'NSL-KDD' },
    { id: 'auth', label: 'Auth & Insider Threat', icon: Shield, module: 'CERT' },
  ];

  const getThreatBadge = () => {
    switch (overallThreatLevel) {
      case 'CRITICAL':
        return {
          text: 'DEFCON 1 // CRITICAL',
          classes: 'bg-rose-950/80 text-rose-400 border-rose-500/50 alert-glow-red animate-pulse',
          dot: 'bg-rose-500'
        };
      case 'HIGH':
        return {
          text: 'ELEVATED THREAT',
          classes: 'bg-amber-950/70 text-amber-400 border-amber-500/50',
          dot: 'bg-amber-500'
        };
      default:
        return {
          text: 'SYSTEM NOMINAL',
          classes: 'bg-emerald-950/60 text-emerald-400 border-emerald-500/30',
          dot: 'bg-emerald-400'
        };
    }
  };

  const threatBadge = getThreatBadge();

  return (
    <header className="border-b border-slate-800 bg-[#0c1220]/95 backdrop-blur sticky top-0 z-50">
      {/* Top Status Strip */}
      <div className="px-6 py-2 border-b border-slate-800/80 flex flex-wrap items-center justify-between text-xs font-mono text-slate-400">
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${systemHealth?.status === 'healthy' ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
              <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${systemHealth?.status === 'healthy' ? 'bg-emerald-500' : 'bg-amber-500'}`}></span>
            </span>
            <span className="font-semibold text-slate-200">
              API GATEWAY: {systemHealth?.status === 'healthy' ? 'ONLINE (PORT 5000)' : 'STANDALONE MODE'}
            </span>
          </div>

          <div className="hidden md:flex items-center space-x-2 text-slate-400">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>LLM ENGINE:</span>
            <span className="text-cyan-300 font-semibold px-1.5 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/50">
              llama-3.3-70b-versatile
            </span>
            {systemHealth?.llm_engine?.groq_client_ready ? (
              <span className="text-emerald-400 text-[10px] flex items-center">
                <CheckCircle2 className="w-3 h-3 mr-0.5" /> GROQ LIVE
              </span>
            ) : (
              <span className="text-amber-400 text-[10px] flex items-center" title="Groq API Key not detected or using deterministic engine">
                <Radio className="w-3 h-3 mr-0.5" /> ACTIVE KNOWLEDGE-BASE
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className={`px-2.5 py-0.5 rounded-full border text-[11px] font-semibold flex items-center space-x-1.5 ${threatBadge.classes}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${threatBadge.dot}`}></span>
            <span>{threatBadge.text}</span>
          </div>

          <div className="flex items-center space-x-1 text-slate-400">
            <Clock className="w-3.5 h-3.5 text-slate-500" />
            <span>{currentTime}</span>
          </div>
        </div>
      </div>

      {/* Main Navbar */}
      <div className="px-6 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-600/30 to-blue-800/30 border border-cyan-500/40 shadow-lg shadow-cyan-950">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-bold tracking-tight text-white font-mono">
                CYBER<span className="text-cyan-400">SOC</span>
              </span>
              <span className="text-[10px] uppercase font-bold tracking-widest px-1.5 py-0.5 rounded bg-blue-900/60 text-cyan-300 border border-cyan-700/50">
                v2.4 Production
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Autonomous Tri-Vector Threat Intelligence Center</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center space-x-2 bg-slate-900/90 p-1.5 rounded-xl border border-slate-800">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-600/20 text-cyan-300 border border-cyan-500/50 shadow-md shadow-cyan-950'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                  isActive ? 'bg-cyan-950 text-cyan-300' : 'bg-slate-800 text-slate-400'
                }`}>
                  {tab.module}
                </span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}

