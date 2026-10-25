import React, { useState, useEffect } from 'react';
import { 
  Activity, Shield, Cpu, AlertTriangle, ArrowRightLeft, 
  Radio, Wifi, Server, ShieldAlert, BarChart3, CheckCircle2
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import LLMReportView from '../components/LLMReportView';
import { FlowAnalyticsChart } from '../components/Charts';
import api from '../services/api';
import defaultLogsData from '../mockData/networkDefaultLogs.json';

// Pre-loaded realistic enterprise network flows
const ENTERPRISE_NETFLOW_LIST = [
  {
    id: 'FLOW-8910',
    protocol_type: 'tcp',
    service: 'private',
    flag: 'S0',
    src_bytes: 0,
    dst_bytes: 0,
    duration: 0.1,
    bytes: 120,
    count: 285,
    srv_count: 285,
    serror_rate: 1.0,
    rerror_rate: 0.0,
    same_srv_rate: 1.0,
    diff_srv_rate: 0.0,
    threatLevel: 'CRITICAL',
    attackCategory: 'DoS (SYN Flood - Neptune)',
    threatProb: 0.965,
  },
  {
    id: 'FLOW-8911',
    protocol_type: 'tcp',
    service: 'telnet',
    flag: 'SF',
    src_bytes: 2800,
    dst_bytes: 14500,
    duration: 14.5,
    bytes: 17300,
    count: 2,
    srv_count: 2,
    serror_rate: 0.0,
    rerror_rate: 0.0,
    same_srv_rate: 1.0,
    diff_srv_rate: 0.0,
    threatLevel: 'CRITICAL',
    attackCategory: 'U2R (Telnet Buffer Overflow)',
    threatProb: 0.942,
  },
  {
    id: 'FLOW-8912',
    protocol_type: 'tcp',
    service: 'other',
    flag: 'REJ',
    src_bytes: 0,
    dst_bytes: 0,
    duration: 0.8,
    bytes: 420,
    count: 140,
    srv_count: 3,
    serror_rate: 0.05,
    rerror_rate: 0.95,
    same_srv_rate: 0.05,
    diff_srv_rate: 0.85,
    threatLevel: 'HIGH',
    attackCategory: 'Probe (Nmap Portsweep)',
    threatProb: 0.825,
  },
  {
    id: 'FLOW-8913',
    protocol_type: 'tcp',
    service: 'http',
    flag: 'SF',
    src_bytes: 340,
    dst_bytes: 4520,
    duration: 1.2,
    bytes: 4860,
    count: 4,
    srv_count: 4,
    serror_rate: 0.0,
    rerror_rate: 0.0,
    same_srv_rate: 1.0,
    diff_srv_rate: 0.0,
    threatLevel: 'LOW',
    attackCategory: 'Normal HTTPS Flow',
    threatProb: 0.038,
  },
  {
    id: 'FLOW-8914',
    protocol_type: 'tcp',
    service: 'smtp',
    flag: 'SF',
    src_bytes: 1024,
    dst_bytes: 380,
    duration: 2.4,
    bytes: 1404,
    count: 1,
    srv_count: 1,
    serror_rate: 0.0,
    rerror_rate: 0.0,
    same_srv_rate: 1.0,
    diff_srv_rate: 0.0,
    threatLevel: 'LOW',
    attackCategory: 'Normal Mail Relay',
    threatProb: 0.024,
  },
  {
    id: 'FLOW-8915',
    protocol_type: 'udp',
    service: 'domain_u',
    flag: 'SF',
    src_bytes: 44,
    dst_bytes: 112,
    duration: 0.05,
    bytes: 156,
    count: 12,
    srv_count: 12,
    serror_rate: 0.0,
    rerror_rate: 0.0,
    same_srv_rate: 1.0,
    diff_srv_rate: 0.0,
    threatLevel: 'LOW',
    attackCategory: 'DNS Resolution',
    threatProb: 0.012,
  },
];

export default function NetworkDashboard({ onThreatUpdate }) {
  const [selectedFlow, setSelectedFlow] = useState(ENTERPRISE_NETFLOW_LIST[0]);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    inspectFlow(ENTERPRISE_NETFLOW_LIST[0]);
  }, []);

  const inspectFlow = async (flow) => {
    setIsLoading(true);
    setSelectedFlow(flow);
    try {
      const payload = {
        protocol_type: flow.protocol_type,
        service: flow.service,
        flag: flow.flag,
        src_bytes: flow.src_bytes,
        dst_bytes: flow.dst_bytes,
        count: flow.count,
        srv_count: flow.srv_count,
        serror_rate: flow.serror_rate,
        rerror_rate: flow.rerror_rate,
        same_srv_rate: flow.same_srv_rate,
        diff_srv_rate: flow.diff_srv_rate,
      };

      const res = await api.analyzeNetwork(payload);
      setAnalysisResult(res);
      if (onThreatUpdate) {
        onThreatUpdate(res.risk_level);
      }
    } catch (err) {
      console.error('Network inspection error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const threatProb = analysisResult?.threat_probability ?? 0.965;
  const attackCategory = analysisResult?.attack_category ?? 'DoS (SYN Flood - Neptune)';
  const threatDetected = analysisResult?.threat_detected === 1 || threatProb >= 0.50;

  return (
    <div id="network-dashboard-view" className="space-y-6">
      {/* Executive Command Header */}
      <div className="p-6 rounded-2xl bg-[#0b1222] border border-slate-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-1">
            <Activity className="w-4 h-4" />
            <span>Network Perimeter Telemetry Vector 02 // NSL-KDD Ingestion Pipeline</span>
          </div>
          <h2 className="text-xl font-black text-white font-mono tracking-tight">
            Network Intrusion Security Operations
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Real-time packet profiling evaluating TCP handshake symmetry, SYN-error rates, and volumetric connection bursts via Random Forest.
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <Wifi className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-300">Ingress Bandwidth: <strong className="text-white">1.42 Gbps</strong></span>
          </div>
          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
            <span className="text-slate-300">Active Netflows: <strong className="text-cyan-300">18,420 /min</strong></span>
          </div>
        </div>
      </div>

      {/* Production Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Intrusion Threat Index"
          value={`${(threatProb * 100).toFixed(1)}%`}
          score={threatProb}
          threshold={0.50}
          subtitle="Random Forest predict_proba()"
          badge={threatDetected ? 'CRITICAL' : 'NOMINAL'}
          status={threatDetected ? 'critical' : 'normal'}
          icon={Radio}
        />
        <MetricCard
          title="Attack Classification"
          value={attackCategory}
          subtitle="Autonomous taxonomy label"
          badge={selectedFlow.flag}
          status={threatDetected ? 'critical' : 'normal'}
          icon={Shield}
        />
        <MetricCard
          title="TCP SYN Error Ratio"
          value={`${((selectedFlow.serror_rate || 0) * 100).toFixed(0)}%`}
          subtitle="Incomplete SYN handshakes"
          badge={selectedFlow.service.toUpperCase()}
          status={(selectedFlow.serror_rate || 0) > 0.5 ? 'critical' : 'normal'}
          icon={Wifi}
        />
        <MetricCard
          title="Traffic Symmetry"
          value={`${selectedFlow.src_bytes}B / ${selectedFlow.dst_bytes}B`}
          subtitle="Source vs Destination volume"
          badge={selectedFlow.protocol_type.toUpperCase()}
          status={selectedFlow.src_bytes > 20000 ? 'warning' : 'normal'}
          icon={ArrowRightLeft}
        />
      </div>

      {/* Prominent High-Severity Intrusion Alert Banner */}
      {threatDetected && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-rose-950/60 via-slate-900/90 to-rose-950/40 border border-rose-600/60 shadow-xl alert-glow-red flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 rounded-xl bg-rose-900/80 text-rose-300 border border-rose-500/80 shrink-0">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold uppercase px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800">
                  Perimeter Anomaly Triggered
                </span>
                <span className="text-xs font-mono text-slate-400">
                  Target Flow: <strong className="text-white">{selectedFlow.id}</strong> ({selectedFlow.protocol_type.toUpperCase()} / {selectedFlow.service})
                </span>
              </div>
              <h4 className="text-sm font-bold text-white mt-1 font-mono">
                Volumetric SYN Flood / DoS Resource Exhaustion Detected
              </h4>
              <p className="text-xs text-slate-300 mt-0.5 font-mono">
                Diagnostics: Connection flag <code className="text-rose-300 bg-rose-950/80 px-1 py-0.5 rounded">{selectedFlow.flag}</code> with {selectedFlow.count} connection requests in past 2s window.
              </p>
            </div>
          </div>

          <div className="text-right font-mono text-xs">
            <div className="text-slate-400 text-[10px]">THREAT CONFIDENCE</div>
            <div className="text-2xl font-black text-rose-400">{(threatProb * 100).toFixed(1)}%</div>
          </div>
        </div>
      )}

      {/* Flow Analytics Visual Chart & Netflow Traces Table */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Network Flow Analytics Chart */}
        <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-[#0b1222] p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center">
                <BarChart3 className="w-4 h-4 mr-1.5" />
                Flow Analytics: Packet Duration vs Bytes Transferred
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
                Plotting flow duration against byte throughput to identify stealth probes vs volumetric floods.
              </p>
            </div>
            <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              Live Scatter Curve
            </span>
          </div>

          <FlowAnalyticsChart data={ENTERPRISE_NETFLOW_LIST} height={250} />

          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-2 border-t border-slate-800/80">
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" />
              <span>Normal Flows</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block" />
              <span>Probe / Recon</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
              <span>Volumetric DoS / Exploit</span>
            </div>
          </div>
        </div>

        {/* Live Network Flow Inspection Table */}
        <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-[#0b1222] p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center">
                <Activity className="w-4 h-4 mr-1.5" />
                Live Netflow Inspection Queue
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
                Click any flow record to run through the NSL-KDD Random Forest model.
              </p>
            </div>
            <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              Ingestion Stream
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0e1628] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                <tr>
                  <th className="p-2.5">Flow ID</th>
                  <th className="p-2.5">Proto / Svc</th>
                  <th className="p-2.5">Flag</th>
                  <th className="p-2.5">Classification</th>
                  <th className="p-2.5 text-right">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-[#090f1d]/50">
                {ENTERPRISE_NETFLOW_LIST.map((flow) => {
                  const isSelected = selectedFlow.id === flow.id;
                  return (
                    <tr
                      key={flow.id}
                      onClick={() => inspectFlow(flow)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="p-2.5 font-bold text-white">{flow.id}</td>
                      <td className="p-2.5 text-slate-300">
                        {flow.protocol_type.toUpperCase()} / {flow.service}
                      </td>
                      <td className="p-2.5">
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                          flow.flag === 'SF' ? 'bg-slate-800 text-slate-300' : 'bg-rose-950 text-rose-300 border border-rose-800'
                        }`}>
                          {flow.flag}
                        </span>
                      </td>
                      <td className="p-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          flow.threatLevel === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          flow.threatLevel === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}>
                          {flow.attackCategory}
                        </span>
                      </td>
                      <td className="p-2.5 text-right font-bold text-cyan-300">
                        {(flow.threatProb * 100).toFixed(1)}%
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Groq LLM Incident Report Dossier */}
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
