import React, { useState } from 'react';
import { 
  Terminal, ShieldAlert, Cpu, Copy, Check, AlertOctagon, 
  Play, CheckCircle2, FileText, ChevronRight, Download, Camera, Printer, Lock
} from 'lucide-react';
import { exportElementAsImage, exportElementAsPdf } from '../utils/exportReport';

export default function LLMReportView({ report, isLoading, onRegenerate }) {
  const [activeScriptTab, setActiveScriptTab] = useState('bash');
  const [copied, setCopied] = useState(false);
  const [executed, setExecuted] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  if (isLoading) {
    return (
      <div className="p-8 rounded-2xl border border-cyan-500/40 bg-[#090f1d] terminal-glow text-center">
        <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-cyan-950/80 border border-cyan-500/50 animate-spin mb-4">
          <Cpu className="w-8 h-8 text-cyan-400" />
        </div>
        <h4 className="text-sm font-mono font-bold text-white uppercase tracking-wider">
          Groq AI Incident Commander Ingesting Telemetry...
        </h4>
        <p className="text-xs text-cyan-300 font-mono mt-1.5">
          Querying <span className="font-bold underline">llama-3.3-70b-versatile</span> for MITRE ATT&CK extraction & containment script synthesis
        </p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-8 rounded-2xl border border-slate-800 bg-[#090e1c]/60 text-center">
        <Terminal className="w-8 h-8 text-slate-600 mx-auto mb-2" />
        <p className="text-xs text-slate-400 font-mono">
          System telemetry is nominal. Automated containment reports trigger when anomaly thresholds are breached.
        </p>
      </div>
    );
  }

  const {
    incident_id = 'INC-20261025-9081',
    severity = 'HIGH',
    threat_summary,
    root_cause,
    confidence_score = 0.95,
    mitre_attack = [],
    remediation = {},
    generated_by = 'Groq LLM (llama-3.3-70b-versatile)',
    timestamp = new Date().toISOString()
  } = report;

  const bashScript = remediation.bash_script || '# No bash remediation script provided';
  const powershellScript = remediation.powershell_script || '# No powershell remediation script provided';
  const currentScript = activeScriptTab === 'bash' ? bashScript : powershellScript;

  const handleCopy = () => {
    navigator.clipboard.writeText(currentScript);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSimulateExecution = () => {
    setExecuted(true);
    setTimeout(() => setExecuted(false), 4500);
  };

  const handleSaveReportImage = async () => {
    setIsExporting(true);
    try {
      await exportElementAsImage('incident-report-dossier', `SOC_${incident_id}_Dossier`);
    } finally {
      setIsExporting(false);
    }
  };

  const handleSaveReportPdf = async () => {
    setIsExporting(true);
    try {
      await exportElementAsPdf('incident-report-dossier', `SOC_${incident_id}_Dossier`);
    } finally {
      setIsExporting(false);
    }
  };

  const severityThemes = {
    CRITICAL: 'bg-rose-950/90 text-rose-300 border-rose-600 alert-glow-red',
    HIGH: 'bg-orange-950/90 text-orange-300 border-orange-600',
    MEDIUM: 'bg-amber-950/90 text-amber-300 border-amber-600',
    LOW: 'bg-emerald-950/90 text-emerald-300 border-emerald-600',
  };

  return (
    <div
      id="incident-report-dossier"
      className="rounded-2xl border border-cyan-500/40 bg-[#070b14] shadow-2xl terminal-glow overflow-hidden text-slate-100"
    >
      {/* Terminal Title Bar */}
      <div className="px-5 py-3.5 bg-[#0c1424] border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="flex space-x-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500/90 inline-block shadow-sm shadow-rose-500"></span>
            <span className="w-3 h-3 rounded-full bg-amber-500/90 inline-block shadow-sm shadow-amber-500"></span>
            <span className="w-3 h-3 rounded-full bg-emerald-500/90 inline-block shadow-sm shadow-emerald-500"></span>
          </div>
          <div className="flex items-center space-x-2 text-xs font-mono">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="text-white font-bold tracking-wider">{incident_id}</span>
            <span className="text-slate-600">//</span>
            <span className="text-slate-400 uppercase font-semibold">Incident Commander Executive Dossier</span>
          </div>
        </div>

        {/* Action Controls & Severity Pill */}
        <div className="flex items-center space-x-2.5">
          <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border ${severityThemes[severity] || severityThemes.HIGH}`}>
            {severity} SEVERITY
          </span>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
            CONFIDENCE: {(confidence_score * 100).toFixed(0)}%
          </span>

          <div className="flex items-center space-x-1 pl-2 border-l border-slate-800 no-print">
            <button
              onClick={handleSaveReportImage}
              disabled={isExporting}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition"
              title="Save Incident Report as High-Res PNG"
            >
              <Camera className="w-3.5 h-3.5 text-cyan-400" />
            </button>
            <button
              onClick={handleSaveReportPdf}
              disabled={isExporting}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition"
              title="Save Incident Report as PDF"
            >
              <FileText className="w-3.5 h-3.5 text-amber-400" />
            </button>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Meta Header */}
        <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b border-slate-800/80 text-xs font-mono text-slate-400">
          <div className="flex items-center space-x-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Synthesis Engine: <strong className="text-white">{generated_by}</strong></span>
          </div>
          <div>
            Dispatched: <span className="text-slate-200">{timestamp}</span>
          </div>
        </div>

        {/* Section A: Threat Summary & Technical Root Cause */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-xl bg-[#0d1526] border border-slate-800">
            <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center mb-2">
              <ShieldAlert className="w-3.5 h-3.5 mr-1.5" />
              Executive Threat Summary
            </h5>
            <p className="text-sm font-sans text-slate-200 leading-relaxed font-normal">
              {threat_summary}
            </p>
          </div>

          <div className="p-4 rounded-xl bg-[#0d1526] border border-slate-800">
            <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400 flex items-center mb-2">
              <AlertOctagon className="w-3.5 h-3.5 mr-1.5" />
              Technical Root Cause Diagnostic
            </h5>
            <p className="text-xs font-mono text-slate-300 leading-relaxed">
              {root_cause}
            </p>
          </div>
        </div>

        {/* Section B: MITRE ATT&CK Matrix Mapping */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400 flex items-center">
              <FileText className="w-3.5 h-3.5 mr-1.5" />
              MITRE ATT&CK Framework Mapping (Enterprise v14)
            </h5>
            <span className="text-[10px] font-mono text-slate-500">Autonomous Technique Correlation</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {mitre_attack && mitre_attack.length > 0 ? (
              mitre_attack.map((item, idx) => (
                <div key={idx} className="p-3.5 rounded-xl bg-[#0c1424] border border-slate-800 hover:border-cyan-500/50 transition-all">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-blue-950 text-cyan-300 border border-blue-800">
                      {item.tactic}
                    </span>
                    <span className="text-xs font-mono font-bold text-amber-300 tracking-wide">
                      {item.technique_id}
                    </span>
                  </div>
                  <h6 className="text-xs font-bold text-white mb-1.5 font-sans">
                    {item.technique_name}
                  </h6>
                  <p className="text-[11px] text-slate-400 leading-normal font-sans">
                    {item.description}
                  </p>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono">No MITRE ATT&CK techniques correlated.</p>
            )}
          </div>
        </div>

        {/* Immediate Containment Checklist */}
        {remediation?.immediate_actions && remediation.immediate_actions.length > 0 && (
          <div className="p-4 rounded-xl bg-[#0c1424] border border-slate-800">
            <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 mb-2.5 flex items-center">
              <Lock className="w-3.5 h-3.5 mr-1.5" />
              Incident Commander Immediate Actions Checklist
            </h5>
            <div className="space-y-2">
              {remediation.immediate_actions.map((act, index) => (
                <div key={index} className="flex items-start space-x-2 text-xs font-sans text-slate-300">
                  <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{act}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Section C: Automated Containment Scripts */}
        <div>
          <div className="flex flex-wrap items-center justify-between gap-3 mb-2.5">
            <div className="flex items-center space-x-2">
              <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 flex items-center">
                <Play className="w-3.5 h-3.5 mr-1.5" />
                Automated Containment Script
              </h5>
              <div className="flex rounded-lg bg-slate-900 p-0.5 border border-slate-800 text-[11px] font-mono no-print">
                <button
                  onClick={() => setActiveScriptTab('bash')}
                  className={`px-3 py-1 rounded transition-colors ${
                    activeScriptTab === 'bash' ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/60' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Bash (Linux / Container)
                </button>
                <button
                  onClick={() => setActiveScriptTab('powershell')}
                  className={`px-3 py-1 rounded transition-colors ${
                    activeScriptTab === 'powershell' ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/60' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  PowerShell (Win / Azure AD)
                </button>
              </div>
            </div>

            <div className="flex items-center space-x-2 no-print">
              <button
                onClick={handleCopy}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-200 border border-slate-700 transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                <span>{copied ? 'Copied' : 'Copy Script'}</span>
              </button>

              <button
                onClick={handleSimulateExecution}
                disabled={executed}
                className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold transition shadow-lg ${
                  executed
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-500 shadow-emerald-950'
                    : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-cyan-950'
                }`}
              >
                {executed ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Containment Dispatched</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Execute Playbook</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Script Code Block */}
          <div className="relative rounded-xl bg-[#040812] border border-slate-800 p-4 font-mono text-xs overflow-x-auto text-emerald-400 shadow-inner">
            <pre className="leading-relaxed whitespace-pre font-mono">
              <code>{currentScript}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
