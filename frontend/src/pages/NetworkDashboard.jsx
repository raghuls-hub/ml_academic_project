import React, { useState, useEffect } from 'react';
import { Activity, Shield, Cpu, Play, RotateCcw, AlertTriangle, ArrowRightLeft, Radio, Layers, Wifi, Server } from 'lucide-react';
import MetricCard from '../components/MetricCard';
import LLMReportView from '../components/LLMReportView';
import LogUploader from '../components/LogUploader';
import api from '../services/api';
import defaultLogsData from '../mockData/networkDefaultLogs.json';

const SAMPLE_NETWORK_CSV = `duration,protocol_type,service,flag,src_bytes,dst_bytes,count,srv_count,serror_rate,rerror_rate,same_srv_rate,diff_srv_rate
0,tcp,http,SF,340,4520,4,4,0.0,0.0,1.0,0.0
0,tcp,private,S0,0,0,285,285,1.0,0.0,1.0,0.0
0,tcp,other,REJ,0,0,140,3,0.05,0.95,0.05,0.85
15,tcp,telnet,SF,2800,14500,2,2,0.0,0.0,1.0,0.0
0,udp,domain_u,SF,44,112,12,12,0.0,0.0,1.0,0.0
0,tcp,smtp,SF,1024,380,1,1,0.0,0.0,1.0,0.0`;

export default function NetworkDashboard({ onThreatUpdate }) {
  const [formData, setFormData] = useState(defaultLogsData.default);
  const [activePreset, setActivePreset] = useState('dos-syn-flood');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [activeTabMode, setActiveTabMode] = useState('single');
  const [errorMessage, setErrorMessage] = useState(null);

  useEffect(() => {
    handleRunAnalysis(defaultLogsData.default);
  }, []);

  const handleInputChange = (field, value) => {
    setFormData((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleSelectPreset = (preset) => {
    setActivePreset(preset.id);
    setFormData(preset.data);
    handleRunAnalysis(preset.data);
  };

  const handleRunAnalysis = async (dataToAnalyze = formData) => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const response = await api.analyzeNetwork(dataToAnalyze);
      setAnalysisResult(response);
      if (onThreatUpdate) {
        onThreatUpdate(response.risk_level);
      }
    } catch (err) {
      console.error('Network analysis error:', err);
      setErrorMessage(err?.response?.data?.message || err?.message || 'Failed to inspect network flow.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleBatchUpload = async (formDataPayload) => {
    const res = await api.analyzeNetwork(formDataPayload);
    if (res.incident_report) {
      setAnalysisResult((prev) => ({
        ...prev,
        incident_report: res.incident_report,
      }));
    }
    return res;
  };

  const threatProb = analysisResult?.threat_probability ?? 0.0;
  const threatDetected = analysisResult?.threat_detected === 1;
  const attackCategory = analysisResult?.attack_category ?? 'Normal Flow';
  const riskLevel = analysisResult?.risk_level ?? 'LOW';

  return (
    <div className="space-y-6">
      {/* Module Title Header */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-[#0c1629] to-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-1">
            <Activity className="w-4 h-4" />
            <span>Telemetry Vector 02 // NSL-KDD Ingestion Pipeline</span>
          </div>
          <h2 className="text-xl font-bold text-white font-mono">
            Network Intrusion Inspector
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            High-speed Random Forest classifier examining connection states, byte symmetry, TCP flags, and SYN-error ratios.
          </p>
        </div>

        {/* View Mode Toggle */}
        <div className="flex items-center space-x-1 p-1 bg-slate-950/80 rounded-xl border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveTabMode('single')}
            className={`px-3 py-1.5 rounded-lg transition ${
              activeTabMode === 'single'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/60 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Flow Inspector Form
          </button>
          <button
            onClick={() => setActiveTabMode('batch')}
            className={`px-3 py-1.5 rounded-lg transition ${
              activeTabMode === 'batch'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/60 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Batch Flow Upload
          </button>
        </div>
      </div>

      {/* Preset Quick Selectors */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-mono text-slate-400 mr-2 flex items-center">
          <Layers className="w-3.5 h-3.5 mr-1 text-cyan-400" />
          Test Presets:
        </span>
        {defaultLogsData.presets.map((preset) => (
          <button
            key={preset.id}
            onClick={() => handleSelectPreset(preset)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition ${
              activePreset === preset.id
                ? 'bg-cyan-950/90 text-cyan-300 border-cyan-500 shadow-md shadow-cyan-950'
                : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            {preset.name}
          </button>
        ))}
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Threat Probability"
          value={`${(threatProb * 100).toFixed(1)}%`}
          score={threatProb}
          threshold={0.50}
          subtitle="Random Forest predict_proba()"
          badge={riskLevel}
          status={threatDetected ? 'critical' : 'normal'}
          icon={Radio}
        />
        <MetricCard
          title="Attack Classification"
          value={attackCategory}
          subtitle="Taxonomy category"
          badge={threatDetected ? 'INTRUSION' : 'NORMAL'}
          status={threatDetected ? 'critical' : 'normal'}
          icon={Shield}
        />
        <MetricCard
          title="SYN Error Rate"
          value={`${((formData.serror_rate || 0) * 100).toFixed(0)}%`}
          subtitle="Incomplete SYN handshakes"
          badge={formData.flag}
          status={(formData.serror_rate || 0) > 0.5 ? 'critical' : 'normal'}
          icon={Wifi}
        />
        <MetricCard
          title="Traffic Symmetry"
          value={`${formData.src_bytes}B / ${formData.dst_bytes}B`}
          subtitle="Source vs Destination volume"
          badge={formData.protocol_type.toUpperCase()}
          status={formData.src_bytes > 50000 && formData.dst_bytes < 100 ? 'warning' : 'normal'}
          icon={ArrowRightLeft}
        />
      </div>

      {/* Main Content Area */}
      {activeTabMode === 'batch' ? (
        <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6">
          <h3 className="text-sm font-mono font-semibold uppercase tracking-wider text-cyan-400 mb-1">
            Batch Network Flow Log Ingestion
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Upload CSV network capture containing protocol, service, flags, byte counters, and error ratios.
          </p>
          <LogUploader
            moduleTitle="Network Intrusion (NSL-KDD)"
            onUploadBatch={handleBatchUpload}
            sampleCsvData={SAMPLE_NETWORK_CSV}
            sampleFileName="network_flow_batch.csv"
          />
        </div>
      ) : (
        /* Single Form Editor */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Flow Parameters Form */}
          <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#0c1322] p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center">
                <Server className="w-4 h-4 mr-1.5" />
                Network Flow Telemetry Attributes
              </h3>
              <span className="text-[11px] font-mono text-slate-500">NSL-KDD Feature Matrix</span>
            </div>

            <div className="grid grid-cols-3 gap-3 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Protocol</label>
                <select
                  value={formData.protocol_type}
                  onChange={(e) => handleInputChange('protocol_type', e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Service</label>
                <select
                  value={formData.service}
                  onChange={(e) => handleInputChange('service', e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="http">http (80)</option>
                  <option value="private">private (custom)</option>
                  <option value="smtp">smtp (25)</option>
                  <option value="ftp_data">ftp_data (20)</option>
                  <option value="telnet">telnet (23)</option>
                  <option value="other">other</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Connection Flag</label>
                <select
                  value={formData.flag}
                  onChange={(e) => handleInputChange('flag', e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="SF">SF (Normal Established)</option>
                  <option value="S0">S0 (SYN without ACK)</option>
                  <option value="REJ">REJ (Connection Rejected)</option>
                  <option value="RSTO">RSTO (Reset by Origin)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Source Bytes (src_bytes)</label>
                <input
                  type="number"
                  value={formData.src_bytes}
                  onChange={(e) => handleInputChange('src_bytes', parseFloat(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Destination Bytes (dst_bytes)</label>
                <input
                  type="number"
                  value={formData.dst_bytes}
                  onChange={(e) => handleInputChange('dst_bytes', parseFloat(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Same Host Count (2s)</label>
                <input
                  type="number"
                  value={formData.count}
                  onChange={(e) => handleInputChange('count', parseFloat(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">SYN Error Rate (0.0 - 1.0)</label>
                <input
                  type="number"
                  step="0.05"
                  min="0"
                  max="1"
                  value={formData.serror_rate}
                  onChange={(e) => handleInputChange('serror_rate', parseFloat(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">REJ Error Rate (0.0 - 1.0)</label>
                <input
                  type="number"
                  step="0.05"
                  min="0"
                  max="1"
                  value={formData.rerror_rate}
                  onChange={(e) => handleInputChange('rerror_rate', parseFloat(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Diff Service Rate (0.0 - 1.0)</label>
                <input
                  type="number"
                  step="0.05"
                  min="0"
                  max="1"
                  value={formData.diff_srv_rate}
                  onChange={(e) => handleInputChange('diff_srv_rate', parseFloat(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center justify-between pt-3">
              <button
                type="button"
                onClick={() => setFormData(defaultLogsData.default)}
                className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-400 border border-slate-800 transition"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset Default</span>
              </button>

              <button
                type="button"
                onClick={() => handleRunAnalysis(formData)}
                disabled={isLoading}
                className="flex items-center space-x-2 px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold shadow-lg shadow-cyan-950 transition disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{isLoading ? 'Inspecting Flow...' : 'Inspect Flow'}</span>
              </button>
            </div>

            {errorMessage && (
              <div className="p-3 rounded-lg bg-rose-950/70 border border-rose-800 text-xs font-mono text-rose-300 flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}
          </div>

          {/* Packet Profiling Radar Display */}
          <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#0c1322] p-6 space-y-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center">
                  <Activity className="w-4 h-4 mr-1.5" />
                  Packet Profiling Breakdown
                </h3>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  threatDetected ? 'bg-rose-950 text-rose-400 border-rose-700' : 'bg-emerald-950 text-emerald-400 border-emerald-700'
                }`}>
                  {threatDetected ? 'INTRUSION DETECTED' : 'NORMAL TRAFFIC'}
                </span>
              </div>

              <div className="mt-4 space-y-3 font-mono text-xs">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="flex justify-between text-slate-400 text-[11px] mb-1">
                    <span>Target Classification</span>
                    <span className="text-white font-bold">{attackCategory}</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Random Forest Probability: <strong className="text-cyan-400">{(threatProb * 100).toFixed(2)}%</strong>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                  <div className="text-[11px] text-slate-400 font-semibold uppercase">Connection Diagnostics:</div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400">Protocol & Service:</span>
                    <span className="text-slate-200">{formData.protocol_type.toUpperCase()} / {formData.service}</span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400">TCP Handshake Flag:</span>
                    <span className={formData.flag === 'SF' ? 'text-emerald-400' : 'text-rose-400 font-bold'}>
                      {formData.flag} ({formData.flag === 'SF' ? 'Established' : 'Abnormal'})
                    </span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400">SYN Flood Likelihood:</span>
                    <span className={formData.serror_rate > 0.5 ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                      {formData.serror_rate > 0.5 ? 'CRITICAL (SYN-Flooding)' : 'Nominal'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono text-slate-400">
              Threshold: <strong className="text-white">0.50 (50%)</strong>
              <p className="text-[11px] text-slate-500 mt-1">
                Automated containment script generation kicks in when Network Threat Probability exceeds 50%.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Automated Groq Incident Report */}
      <div className="pt-2">
        <div className="flex items-center space-x-2 mb-3">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-mono font-semibold uppercase tracking-wider text-white">
            Automated SOC Incident Response Playbook (Groq llama-3.3-70b-versatile)
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

