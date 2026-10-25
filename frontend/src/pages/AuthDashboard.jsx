import React, { useState, useEffect } from 'react';
import { Shield, Cpu, Play, RotateCcw, AlertTriangle, Clock, HardDrive, FileText, UserX, UserCheck, Layers, Lock, Flame } from 'lucide-react';
import MetricCard from '../components/MetricCard';
import LLMReportView from '../components/LLMReportView';
import LogUploader from '../components/LogUploader';
import api from '../services/api';
import defaultLogsData from '../mockData/authDefaultLogs.json';

const SAMPLE_AUTH_CSV = `user_id,login_hour,is_weekend,failed_logins,usb_device_connected,files_accessed,data_transfer_mb,privileged_commands_count
USR-1042,10,0,0,0,18,12.5,0
USR-8819,3,1,5,1,380,840.5,4
USR-3051,22,0,1,0,65,45.0,1
USR-9901,2,0,12,0,195,310.0,7
USR-1002,14,0,0,0,25,8.0,0
USR-5541,4,1,3,1,210,540.0,3`;

export default function AuthDashboard({ onThreatUpdate }) {
  const [formData, setFormData] = useState(defaultLogsData.default);
  const [activePreset, setActivePreset] = useState('insider-exfiltration');
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
      const response = await api.analyzeAuth(dataToAnalyze);
      setAnalysisResult(response);
      if (onThreatUpdate) {
        onThreatUpdate(response.risk_level);
      }
    } catch (err) {
      console.error('Auth analysis error:', err);
      setErrorMessage(err?.response?.data?.message || err?.message || 'Failed to analyze user behavior.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleBatchUpload = async (formDataPayload) => {
    const res = await api.analyzeAuth(formDataPayload);
    if (res.incident_report) {
      setAnalysisResult((prev) => ({
        ...prev,
        incident_report: res.incident_report,
      }));
    }
    return res;
  };

  const anomalyScore = analysisResult?.anomaly_score ?? 0.0;
  const decisionFunction = analysisResult?.decision_function ?? 0.0;
  const isAnomaly = analysisResult?.is_anomaly ?? false;
  const riskLevel = analysisResult?.risk_level ?? 'LOW';
  const riskFactors = analysisResult?.risk_factors || [];

  return (
    <div className="space-y-6">
      {/* Module Title Header */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-[#0c1629] to-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-1">
            <Shield className="w-4 h-4" />
            <span>Telemetry Vector 03 // CERT Insider Threat Dataset</span>
          </div>
          <h2 className="text-xl font-bold text-white font-mono">
            Auth & Insider Threat Engine
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Continuous behavioral anomaly profiling monitoring off-hours logins, USB media insertions, failed auth spikes, and mass data staging.
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
            User Behavior Sliders
          </button>
          <button
            onClick={() => setActiveTabMode('batch')}
            className={`px-3 py-1.5 rounded-lg transition ${
              activeTabMode === 'batch'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/60 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Batch Auth Ingestion
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
          title="Normalized Anomaly Score"
          value={`${(anomalyScore * 100).toFixed(1)}%`}
          score={anomalyScore}
          threshold={0.65}
          subtitle="Sigmoid mapped decision scale"
          badge={riskLevel}
          status={isAnomaly ? 'critical' : 'normal'}
          icon={Flame}
        />
        <MetricCard
          title="Isolation Decision Score"
          value={decisionFunction.toFixed(4)}
          subtitle="Raw decision (negative = outlier)"
          badge={analysisResult?.prediction === -1 ? 'OUTLIER (-1)' : 'INLIER (+1)'}
          status={analysisResult?.prediction === -1 ? 'critical' : 'normal'}
          icon={Shield}
        />
        <MetricCard
          title="Access Schedule"
          value={`${String(formData.login_hour).padStart(2, '0')}:00 HRS`}
          subtitle={formData.is_weekend ? 'Weekend Shift Access' : 'Weekday Access'}
          badge={formData.login_hour < 6 || formData.login_hour > 20 ? 'AFTER HOURS' : 'BUSINESS HOURS'}
          status={formData.login_hour < 6 || formData.login_hour > 20 ? 'warning' : 'normal'}
          icon={Clock}
        />
        <MetricCard
          title="Removable Media"
          value={formData.usb_device_connected ? 'CONNECTED' : 'NONE'}
          subtitle="USB mass storage interface"
          badge={formData.usb_device_connected ? 'ALERT' : 'CLEAR'}
          status={formData.usb_device_connected ? 'critical' : 'normal'}
          icon={HardDrive}
        />
      </div>

      {/* Main Content Area */}
      {activeTabMode === 'batch' ? (
        <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6">
          <h3 className="text-sm font-mono font-semibold uppercase tracking-wider text-cyan-400 mb-1">
            Batch User Behavior Audit Ingestion
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Upload CSV telemetry containing user_id, login_hour, failed_logins, usb_device_connected, and data transfer volumes.
          </p>
          <LogUploader
            moduleTitle="Auth & Insider Threat (CERT)"
            onUploadBatch={handleBatchUpload}
            sampleCsvData={SAMPLE_AUTH_CSV}
            sampleFileName="cert_auth_telemetry.csv"
          />
        </div>
      ) : (
        /* Single Form Editor */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* User Access Timing Sliders */}
          <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#0c1322] p-6 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center">
                <Clock className="w-4 h-4 mr-1.5" />
                User Access Timing & Activity Sliders
              </h3>
              <span className="text-[11px] font-mono text-slate-500">CERT Profiler</span>
            </div>

            {/* User ID Field */}
            <div className="flex items-center space-x-3 text-xs font-mono">
              <label className="text-slate-400 w-32 shrink-0">Account Identity:</label>
              <input
                type="text"
                value={formData.user_id}
                onChange={(e) => handleInputChange('user_id', e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-bold focus:border-cyan-500 focus:outline-none"
              />
            </div>

            {/* Slider 1: Login Hour (0 - 23) */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-300 flex items-center">
                  <Clock className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />
                  Authentication Hour (00:00 - 23:00)
                </span>
                <span className="text-cyan-400 font-bold">{formData.login_hour}:00 hrs</span>
              </div>
              <input
                type="range"
                min="0"
                max="23"
                value={formData.login_hour}
                onChange={(e) => handleInputChange('login_hour', parseInt(e.target.value))}
                className="w-full accent-cyan-400 h-2 bg-slate-900 rounded-lg cursor-pointer"
              />
              <div className="flex justify-between text-[10px] font-mono text-slate-500 px-1">
                <span>00:00 (Midnight)</span>
                <span className="text-emerald-500/80">09:00 - 17:00 (Standard Shift)</span>
                <span>23:00</span>
              </div>
            </div>

            {/* Slider 2: Failed Login Attempts (0 - 15) */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-300 flex items-center">
                  <Lock className="w-3.5 h-3.5 mr-1.5 text-amber-400" />
                  Failed Authentication Attempts
                </span>
                <span className={formData.failed_logins >= 3 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                  {formData.failed_logins} failures
                </span>
              </div>
              <input
                type="range"
                min="0"
                max="15"
                value={formData.failed_logins}
                onChange={(e) => handleInputChange('failed_logins', parseInt(e.target.value))}
                className="w-full accent-amber-400 h-2 bg-slate-900 rounded-lg cursor-pointer"
              />
            </div>

            {/* Slider 3: Files Accessed (0 - 500) */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-300 flex items-center">
                  <FileText className="w-3.5 h-3.5 mr-1.5 text-purple-400" />
                  Sensitive Files Read / Touched
                </span>
                <span className={formData.files_accessed > 150 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                  {formData.files_accessed} files
                </span>
              </div>
              <input
                type="range"
                min="0"
                max="500"
                step="5"
                value={formData.files_accessed}
                onChange={(e) => handleInputChange('files_accessed', parseInt(e.target.value))}
                className="w-full accent-purple-400 h-2 bg-slate-900 rounded-lg cursor-pointer"
              />
            </div>

            {/* Slider 4: Data Transfer Volume (0 - 1000 MB) */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-300 flex items-center">
                  <HardDrive className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />
                  Outbound Data Staging Volume (MB)
                </span>
                <span className={formData.data_transfer_mb > 300 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                  {formData.data_transfer_mb} MB
                </span>
              </div>
              <input
                type="range"
                min="0"
                max="1000"
                step="10"
                value={formData.data_transfer_mb}
                onChange={(e) => handleInputChange('data_transfer_mb', parseFloat(e.target.value))}
                className="w-full accent-cyan-400 h-2 bg-slate-900 rounded-lg cursor-pointer"
              />
            </div>

            {/* Binary Toggles: Weekend & USB Media */}
            <div className="grid grid-cols-2 gap-4 pt-2 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-white block font-medium">Weekend Access</span>
                  <span className="text-slate-400 text-[10px]">{formData.is_weekend ? 'Saturday/Sunday' : 'Standard Weekday'}</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleInputChange('is_weekend', formData.is_weekend ? 0 : 1)}
                  className={`w-11 h-6 rounded-full transition-colors relative ${formData.is_weekend ? 'bg-amber-500' : 'bg-slate-700'}`}
                >
                  <span className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-transform ${formData.is_weekend ? 'left-6' : 'left-1'}`} />
                </button>
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-white block font-medium">Removable USB Storage</span>
                  <span className="text-slate-400 text-[10px]">{formData.usb_device_connected ? 'Device Mounted' : 'No Devices'}</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleInputChange('usb_device_connected', formData.usb_device_connected ? 0 : 1)}
                  className={`w-11 h-6 rounded-full transition-colors relative ${formData.usb_device_connected ? 'bg-rose-500' : 'bg-slate-700'}`}
                >
                  <span className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-transform ${formData.usb_device_connected ? 'left-6' : 'left-1'}`} />
                </button>
              </div>
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
                <span>{isLoading ? 'Evaluating Telemetry...' : 'Evaluate User Risk'}</span>
              </button>
            </div>

            {errorMessage && (
              <div className="p-3 rounded-lg bg-rose-950/70 border border-rose-800 text-xs font-mono text-rose-300 flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}
          </div>

          {/* Behavior Profile Radar Display */}
          <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#0c1322] p-6 space-y-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center">
                  <Shield className="w-4 h-4 mr-1.5" />
                  Isolation Forest Decision Boundary
                </h3>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  isAnomaly ? 'bg-rose-950 text-rose-400 border-rose-700' : 'bg-emerald-950 text-emerald-400 border-emerald-700'
                }`}>
                  {isAnomaly ? 'INSIDER THREAT' : 'AUTHORIZED ACCESS'}
                </span>
              </div>

              <div className="mt-4 space-y-3 font-mono text-xs">
                <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-slate-400 text-[11px] mb-1">DECISION FUNCTION VALUE:</div>
                  <div className="flex items-baseline space-x-2">
                    <span className={`text-xl font-bold ${decisionFunction < 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {decisionFunction.toFixed(4)}
                    </span>
                    <span className="text-[11px] text-slate-400">
                      {decisionFunction < 0 ? '(Negative = Anomaly Outlier)' : '(Positive = Baseline Inlier)'}
                    </span>
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                  <div className="text-[11px] text-slate-400 font-semibold uppercase">Flagged Risk Indicators:</div>
                  {riskFactors && riskFactors.length > 0 ? (
                    <div className="space-y-1.5">
                      {riskFactors.map((factor, idx) => (
                        <div key={idx} className="flex items-start space-x-2 text-[11px] text-slate-300">
                          <span className="text-amber-400 font-bold shrink-0">►</span>
                          <span>{factor}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] text-slate-500">No abnormal behavior detected.</p>
                  )}
                </div>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono text-slate-400">
              Threshold: <strong className="text-white">0.65 (or Prediction = -1)</strong>
              <p className="text-[11px] text-slate-500 mt-1">
                If the employee's behavior deviates past the decision boundary, automated credential revocation and incident response playbooks trigger immediately.
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

