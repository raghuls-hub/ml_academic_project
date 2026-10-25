import React, { useState, useEffect } from 'react';
import { 
  Shield, Cpu, Activity, Clock, Terminal, CheckCircle2, 
  Radio, Download, FileText, Image as ImageIcon, UploadCloud, ChevronDown
} from 'lucide-react';
import { exportElementAsImage, exportElementAsPdf } from '../utils/exportReport';

export default function Navbar({ 
  activeTab, 
  setActiveTab, 
  systemHealth, 
  overallThreatLevel = 'CRITICAL',
  onOpenBatchModal 
}) {
  const [currentTime, setCurrentTime] = useState(new Date().toUTCString().slice(17, 25) + ' UTC');
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toUTCString().slice(17, 25) + ' UTC');
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const tabs = [
    { id: 'host', label: 'Host Security & Syscalls', icon: Terminal, module: 'BETH' },
    { id: 'network', label: 'Network Intrusion Ops', icon: Activity, module: 'NSL-KDD' },
    { id: 'auth', label: 'Auth & Insider Threat', icon: Shield, module: 'CERT' },
  ];

  const getThreatBadge = () => {
    switch (overallThreatLevel) {
      case 'CRITICAL':
        return {
          text: 'DEFCON 1 // ACTIVE INCIDENT',
          classes: 'bg-rose-950/80 text-rose-400 border-rose-500/60 alert-glow-red animate-pulse',
          dot: 'bg-rose-500'
        };
      case 'HIGH':
        return {
          text: 'ELEVATED DEFENSE POSTURE',
          classes: 'bg-amber-950/80 text-amber-400 border-amber-500/60',
          dot: 'bg-amber-500'
        };
      default:
        return {
          text: 'DEFCON 5 // SYSTEM NOMINAL',
          classes: 'bg-emerald-950/70 text-emerald-400 border-emerald-500/40',
          dot: 'bg-emerald-400'
        };
    }
  };

  const threatBadge = getThreatBadge();

  const handleExportPNG = async () => {
    setIsExporting(true);
    setShowExportMenu(false);
    try {
      await exportElementAsImage('soc-command-center-root', `SOC_Executive_Report_${activeTab.toUpperCase()}`);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportPDF = async () => {
    setIsExporting(true);
    setShowExportMenu(false);
    try {
      await exportElementAsPdf('soc-command-center-root', `SOC_Executive_Dossier_${activeTab.toUpperCase()}`);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <header className="border-b border-slate-800 bg-[#090e1a]/95 backdrop-blur sticky top-0 z-50 shadow-2xl">
      {/* Top Threat & Health Strip */}
      <div className="px-6 py-2 border-b border-slate-800/80 flex flex-wrap items-center justify-between text-xs font-mono text-slate-400">
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                systemHealth?.status === 'healthy' ? 'bg-emerald-400' : 'bg-emerald-400'
              }`}></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
            <span className="font-semibold text-slate-200">
              CLUSTER GATEWAY: ONLINE
            </span>
          </div>

          <div className="hidden lg:flex items-center space-x-2 text-slate-400">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>LLM INCIDENT COMMANDER:</span>
            <span className="text-cyan-300 font-semibold px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/60">
              llama-3.3-70b-versatile
            </span>
            <span className="text-emerald-400 text-[10px] font-bold flex items-center">
              <CheckCircle2 className="w-3 h-3 mr-0.5" /> GROQ ACTIVE
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className={`px-3 py-0.5 rounded-full border text-[11px] font-bold flex items-center space-x-2 ${threatBadge.classes}`}>
            <span className={`w-2 h-2 rounded-full ${threatBadge.dot}`}></span>
            <span>{threatBadge.text}</span>
          </div>

          <div className="flex items-center space-x-1.5 text-slate-400 bg-slate-900/60 px-2.5 py-0.5 rounded border border-slate-800">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-200">{currentTime}</span>
          </div>
        </div>
      </div>

      {/* Main Command Bar */}
      <div className="px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 via-blue-600/20 to-purple-700/20 border border-cyan-500/50 shadow-lg shadow-cyan-950">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-black tracking-tight text-white font-mono">
                CYBER<span className="text-cyan-400">SOC</span>
              </span>
              <span className="text-[10px] font-bold tracking-widest px-2 py-0.5 rounded bg-blue-950 text-cyan-300 border border-cyan-700/60 uppercase">
                Enterprise Defense
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Production AI Threat Operations Center</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center space-x-1.5 bg-[#0d1424] p-1.5 rounded-xl border border-slate-800/90 shadow-inner">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-mono font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/25 to-blue-600/25 text-cyan-300 border border-cyan-500/60 shadow-lg shadow-cyan-950 font-bold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                  isActive ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'bg-slate-800 text-slate-500'
                }`}>
                  {tab.module}
                </span>
              </button>
            );
          })}
        </nav>

        {/* Global Action Controls: Batch Modal & Export */}
        <div className="flex items-center space-x-2.5">
          {/* Slide-over / Modal Batch Trigger */}
          <button
            onClick={onOpenBatchModal}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-700/80 transition shadow-sm hover:border-cyan-500/40"
            title="Import and ingest batch CSV logs"
          >
            <UploadCloud className="w-3.5 h-3.5 text-cyan-400" />
            <span>Batch Log Ingest</span>
          </button>

          {/* Export Report Dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowExportMenu(!showExportMenu)}
              disabled={isExporting}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold shadow-lg shadow-cyan-950 transition"
            >
              <Download className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>{isExporting ? 'Generating...' : 'Export Dossier'}</span>
              <ChevronDown className="w-3 h-3 stroke-[2.5]" />
            </button>

            {showExportMenu && (
              <div className="absolute right-0 mt-2 w-52 rounded-xl bg-[#0f172a] border border-slate-700 shadow-2xl py-1.5 z-50 text-xs font-mono">
                <div className="px-3 py-1.5 text-[10px] text-slate-400 uppercase font-semibold border-b border-slate-800">
                  Export Executive Documentation
                </div>
                <button
                  onClick={handleExportPNG}
                  className="w-full text-left px-3.5 py-2 text-slate-200 hover:bg-cyan-950/70 hover:text-cyan-300 flex items-center space-x-2 transition"
                >
                  <ImageIcon className="w-4 h-4 text-cyan-400" />
                  <span>Download High-Res PNG</span>
                </button>
                <button
                  onClick={handleExportPDF}
                  className="w-full text-left px-3.5 py-2 text-slate-200 hover:bg-cyan-950/70 hover:text-cyan-300 flex items-center space-x-2 transition"
                >
                  <FileText className="w-4 h-4 text-amber-400" />
                  <span>Download PDF Dossier</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
