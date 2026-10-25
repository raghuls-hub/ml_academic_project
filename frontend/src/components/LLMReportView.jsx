import React, { useState } from 'react';
import { 
  Terminal, ShieldAlert, Cpu, Copy, Check, AlertOctagon, 
  ExternalLink, Play, CheckCircle2, FileText, ChevronRight, CornerDownRight 
} from 'lucide-react';

export default function LLMReportView({ report, isLoading, onRegenerate }) {
  const [activeScriptTab, setActiveScriptTab] = useState('bash');
  const [copied, setCopied] = useState(false);
  const [executed, setExecuted] = useState(false);

  if (isLoading) {
    return (
      <div className="p-8 rounded-xl border border-cyan-500/30 bg-[#0b1322] terminal-glow text-center">
        <div className="inline-flex items-center justify-center p-3 rounded-xl bg-cyan-950/80 border border-cyan-500/40 animate-spin mb-4">
          <Cpu className="w-8 h-8 text-cyan-400" />
        </div>
        <h4 className="text-base font-mono font-semibold text-white">
          Groq LLM Incident Commander Active...
        </h4>
        <p className="text-xs text-cyan-300 font-mono mt-1">
          Querying model: <span className="font-bold">llama-3.3-70b-versatile</span> for MITRE ATT&CK extraction & remediation script synthesis
        </p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-8 rounded-xl border border-slate-800 bg-[#0d1526]/50 text-center">
        <Terminal className="w-8 h-8 text-slate-600 mx-auto mb-2" />
        <p className="text-xs text-slate-400 font-mono">
          No active anomaly threshold crossed. SOC automated incident response will trigger when telemetry indicates high threat levels.
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
    setTimeout(() => setExecuted(false), 4000);
  };

  const severityThemes = {
    CRITICAL: 'bg-rose-950 text-rose-300 border-rose-600 alert-glow-red',
    HIGH: 'bg-orange-950 text-orange-300 border-orange-600',
    MEDIUM: 'bg-amber-950 text-amber-300 border-amber-600',
    LOW: 'bg-emerald-950 text-emerald-300 border-emerald-600',
  };

  return (
    <div className="rounded-xl border border-cyan-500/40 bg-[#090f1d] shadow-2xl terminal-glow overflow-hidden">
      {/* Terminal Title Bar */}
      <div className="px-5 py-3 bg-[#0f172a] border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="flex space-x-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block"></span>
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block"></span>
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block"></span>
          </div>
          <div className="flex items-center space-x-2 text-xs font-mono">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="text-white font-semibold">{incident_id}</span>
            <span className="text-slate-500">//</span>
            <span className="text-slate-400">AUTOMATED INCIDENT RESPONSE REPORT</span>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border ${severityThemes[severity] || severityThemes.HIGH}`}>
            {severity} SEVERITY
          </span>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800">
            CONFIDENCE: {(confidence_score * 100).toFixed(0)}%
          </span>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Meta Header */}
        <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b border-slate-800/80 text-xs font-mono text-slate-400">
          <div className="flex items-center space-x-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>AI Model: <strong className="text-slate-200">{generated_by}</strong></span>
          </div>
          <div>
            Timestamp: <span className="text-slate-200">{timestamp}</span>
          </div>
        </div>

        {/* Section A: Threat Summary & Root Cause */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800">
            <h5 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center mb-2">
              <ShieldAlert className="w-3.5 h-3.5 mr-1.5" />
              Threat Summary
            </h5>
            <p className="text-sm font-sans text-slate-200 leading-relaxed">
              {threat_summary}
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800">
            <h5 className="text-xs font-mono font-semibold uppercase tracking-wider text-rose-400 flex items-center mb-2">
              <AlertOctagon className="w-3.5 h-3.5 mr-1.5" />
              Technical Root Cause
            </h5>
            <p className="text-xs font-mono text-slate-300 leading-relaxed">
              {root_cause}
            </p>
          </div>
        </div>

        {/* Section B: MITRE ATT&CK Mapping */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h5 className="text-xs font-mono font-semibold uppercase tracking-wider text-amber-400 flex items-center">
              <FileText className="w-3.5 h-3.5 mr-1.5" />
              MITRE ATT&CK Framework Mapping
            </h5>
            <span className="text-[11px] font-mono text-slate-500">Matrix Enterprise v14</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {mitre_attack && mitre_attack.length > 0 ? (
              mitre_attack.map((item, idx) => (
                <div key={idx} className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-cyan-500/50 transition-all">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded bg-blue-950 text-cyan-300 border border-blue-800">
                      {item.tactic}
                    </span>
                    <span className="text-xs font-mono font-bold text-amber-300">
                      {item.technique_id}
                    </span>
                  </div>
                  <h6 className="text-xs font-semibold text-white mb-1.5">
                    {item.technique_name}
                  </h6>
                  <p className="text-[11px] text-slate-400 leading-normal">
                    {item.description}
                  </p>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono">No MITRE ATT&CK tags provided.</p>
            )}
          </div>
        </div>

        {/* Immediate Containment Actions Checklist */}
        {remediation?.immediate_actions && remediation.immediate_actions.length > 0 && (
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
            <h5 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 mb-2.5">
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

        {/* Section C: Automated Remediation Script */}
        <div>
          <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
            <div className="flex items-center space-x-2">
              <h5 className="text-xs font-mono font-semibold uppercase tracking-wider text-emerald-400 flex items-center">
                <Play className="w-3.5 h-3.5 mr-1.5" />
                Automated Containment Script
              </h5>
              <div className="flex rounded-lg bg-slate-900 p-0.5 border border-slate-800 text-[11px] font-mono">
                <button
                  onClick={() => setActiveScriptTab('bash')}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    activeScriptTab === 'bash' ? 'bg-cyan-950 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Bash (Linux)
                </button>
                <button
                  onClick={() => setActiveScriptTab('powershell')}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    activeScriptTab === 'powershell' ? 'bg-cyan-950 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  PowerShell (Win)
                </button>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={handleCopy}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                <span>{copied ? 'Copied' : 'Copy Script'}</span>
              </button>

              <button
                onClick={handleSimulateExecution}
                disabled={executed}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                  executed
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-500'
                    : 'bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-950'
                }`}
              >
                {executed ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Remediation Dispatched</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Execute Containment</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Script Code Block */}
          <div className="relative rounded-lg bg-[#040810] border border-slate-800 p-4 font-mono text-xs overflow-x-auto text-emerald-400">
            <pre className="leading-relaxed whitespace-pre">
              <code>{currentScript}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

