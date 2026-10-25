import React, { useState, useEffect } from 'react';
import { 
  Shield, Cpu, AlertTriangle, Clock, HardDrive, 
  FileText, ShieldAlert, UserX, UserCheck, Flame, Users, Lock
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import LLMReportView from '../components/LLMReportView';
import { UserAccessMatrixChart } from '../components/Charts';
import api from '../services/api';
import defaultLogsData from '../mockData/authDefaultLogs.json';

// Pre-loaded realistic enterprise user behavioral audit
const ENTERPRISE_USER_LIST = [
  {
    user_id: 'USR-8819',
    department: 'Data Engineering',
    login_hour: 3,
    is_weekend: 1,
    failed_logins: 5,
    usb_device_connected: 1,
    files_accessed: 380,
    data_transfer_mb: 840.5,
    privileged_commands_count: 4,
    anomaly_score: 0.915,
    decision_function: -0.415,
    risk: 'CRITICAL',
    status: 'EXFILTRATION OUTLIER',
  },
  {
    user_id: 'USR-9901',
    department: 'DevOps / Infra',
    login_hour: 2,
    is_weekend: 0,
    failed_logins: 12,
    usb_device_connected: 0,
    files_accessed: 195,
    data_transfer_mb: 310.0,
    privileged_commands_count: 7,
    anomaly_score: 0.880,
    decision_function: -0.380,
    risk: 'CRITICAL',
    status: 'ACCOUNT TAKEOVER',
  },
  {
    user_id: 'USR-3051',
    department: 'Software Engineering',
    login_hour: 22,
    is_weekend: 0,
    failed_logins: 1,
    usb_device_connected: 0,
    files_accessed: 65,
    data_transfer_mb: 45.0,
    privileged_commands_count: 1,
    anomaly_score: 0.485,
    decision_function: 0.015,
    risk: 'MEDIUM',
    status: 'AFTER-HOURS WORK',
  },
  {
    user_id: 'USR-1042',
    department: 'Financial Analyst',
    login_hour: 10,
    is_weekend: 0,
    failed_logins: 0,
    usb_device_connected: 0,
    files_accessed: 18,
    data_transfer_mb: 12.5,
    privileged_commands_count: 0,
    anomaly_score: 0.045,
    decision_function: 0.455,
    risk: 'LOW',
    status: 'BASELINE NORMAL',
  },
  {
    user_id: 'USR-1002',
    department: 'Product Operations',
    login_hour: 14,
    is_weekend: 0,
    failed_logins: 0,
    usb_device_connected: 0,
    files_accessed: 25,
    data_transfer_mb: 8.0,
    privileged_commands_count: 0,
    anomaly_score: 0.038,
    decision_function: 0.462,
    risk: 'LOW',
    status: 'BASELINE NORMAL',
  },
  {
    user_id: 'USR-4421',
    department: 'HR Operations',
    login_hour: 9,
    is_weekend: 0,
    failed_logins: 0,
    usb_device_connected: 0,
    files_accessed: 28,
    data_transfer_mb: 14.0,
    privileged_commands_count: 0,
    anomaly_score: 0.042,
    decision_function: 0.458,
    risk: 'LOW',
    status: 'BASELINE NORMAL',
  },
];

// 24-hour access timeline data
const HOURLY_ACCESS_DATA = [
  { hour: 0, totalAccesses: 4, isOutlier: false },
  { hour: 1, totalAccesses: 2, isOutlier: false },
  { hour: 2, totalAccesses: 8, isOutlier: true },   // Brute-force outlier
  { hour: 3, totalAccesses: 11, isOutlier: true },  // 3 AM USB exfiltration
  { hour: 4, totalAccesses: 3, isOutlier: false },
  { hour: 5, totalAccesses: 5, isOutlier: false },
  { hour: 6, totalAccesses: 12, isOutlier: false },
  { hour: 7, totalAccesses: 28, isOutlier: false },
  { hour: 8, totalAccesses: 65, isOutlier: false },
  { hour: 9, totalAccesses: 142, isOutlier: false },
  { hour: 10, totalAccesses: 185, isOutlier: false },
  { hour: 11, totalAccesses: 160, isOutlier: false },
  { hour: 12, totalAccesses: 120, isOutlier: false },
  { hour: 13, totalAccesses: 145, isOutlier: false },
  { hour: 14, totalAccesses: 178, isOutlier: false },
  { hour: 15, totalAccesses: 155, isOutlier: false },
  { hour: 16, totalAccesses: 130, isOutlier: false },
  { hour: 17, totalAccesses: 85, isOutlier: false },
  { hour: 18, totalAccesses: 42, isOutlier: false },
  { hour: 19, totalAccesses: 24, isOutlier: false },
  { hour: 20, totalAccesses: 18, isOutlier: false },
  { hour: 21, totalAccesses: 12, isOutlier: false },
  { hour: 22, totalAccesses: 15, isOutlier: false },
  { hour: 23, totalAccesses: 6, isOutlier: false },
];

export default function AuthDashboard({ onThreatUpdate }) {
  const [selectedUser, setSelectedUser] = useState(ENTERPRISE_USER_LIST[0]);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    inspectUser(ENTERPRISE_USER_LIST[0]);
  }, []);

  const inspectUser = async (user) => {
    setIsLoading(true);
    setSelectedUser(user);
    try {
      const payload = {
        user_id: user.user_id,
        login_hour: user.login_hour,
        is_weekend: user.is_weekend,
        failed_logins: user.failed_logins,
        usb_device_connected: user.usb_device_connected,
        files_accessed: user.files_accessed,
        data_transfer_mb: user.data_transfer_mb,
        privileged_commands_count: user.privileged_commands_count,
      };

      const res = await api.analyzeAuth(payload);
      setAnalysisResult(res);
      if (onThreatUpdate) {
        onThreatUpdate(res.risk_level);
      }
    } catch (err) {
      console.error('Auth inspection error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const anomalyScore = analysisResult?.anomaly_score ?? 0.915;
  const decisionFunction = analysisResult?.decision_function ?? -0.415;
  const isAnomaly = analysisResult?.is_anomaly ?? true;
  const riskFactors = analysisResult?.risk_factors || [
    '3 AM weekend authentication',
    'Mass data staging (840 MB)',
    'Removable USB storage drive mounted',
  ];

  return (
    <div id="auth-dashboard-view" className="space-y-6">
      {/* Executive Command Header */}
      <div className="p-6 rounded-2xl bg-[#0b1222] border border-slate-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-1">
            <Shield className="w-4 h-4" />
            <span>Identity & Access Telemetry Vector 03 // CERT Insider Threat Pipeline</span>
          </div>
          <h2 className="text-xl font-black text-white font-mono tracking-tight">
            Authentication & Insider Threat Operations
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Behavioral access baseline profiling via Isolation Forest detecting off-hours access, USB insertions, and credential brute-forcing.
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <Users className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-300">Monitored Accounts: <strong className="text-white">420 Active</strong></span>
          </div>
          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
            <span className="text-slate-300">Flagged Outliers: <strong className="text-rose-400">2 Critical</strong></span>
          </div>
        </div>
      </div>

      {/* Production Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Normalized Risk Index"
          value={`${(anomalyScore * 100).toFixed(1)}%`}
          score={anomalyScore}
          threshold={0.65}
          subtitle="Sigmoid decision boundary scale"
          badge={isAnomaly ? 'CRITICAL' : 'BASELINE'}
          status={isAnomaly ? 'critical' : 'normal'}
          icon={Flame}
        />
        <MetricCard
          title="Decision Function Score"
          value={decisionFunction.toFixed(4)}
          subtitle="Negative values denote outliers"
          badge={decisionFunction < 0 ? 'OUTLIER (-1)' : 'INLIER (+1)'}
          status={decisionFunction < 0 ? 'critical' : 'normal'}
          icon={Shield}
        />
        <MetricCard
          title="Access Timing Profile"
          value={`${String(selectedUser.login_hour).padStart(2, '0')}:00 HRS`}
          subtitle={selectedUser.is_weekend ? 'Weekend Facility Access' : 'Standard Weekday Shift'}
          badge={selectedUser.login_hour < 6 || selectedUser.login_hour > 20 ? 'OFF-HOURS' : 'BUSINESS'}
          status={selectedUser.login_hour < 6 || selectedUser.login_hour > 20 ? 'warning' : 'normal'}
          icon={Clock}
        />
        <MetricCard
          title="Removable Media Interface"
          value={selectedUser.usb_device_connected ? 'STORAGE MOUNTED' : 'DISCONNECTED'}
          subtitle="Physical USB exfiltration monitor"
          badge={selectedUser.usb_device_connected ? 'ALERT' : 'SECURE'}
          status={selectedUser.usb_device_connected ? 'critical' : 'normal'}
          icon={HardDrive}
        />
      </div>

      {/* Prominent High-Severity Insider Threat Alert Banner */}
      {isAnomaly && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-rose-950/60 via-slate-900/90 to-rose-950/40 border border-rose-600/60 shadow-xl alert-glow-red flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 rounded-xl bg-rose-900/80 text-rose-300 border border-rose-500/80 shrink-0">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold uppercase px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800">
                  Insider Threat Detected
                </span>
                <span className="text-xs font-mono text-slate-400">
                  Target Identity: <strong className="text-white">{selectedUser.user_id}</strong> ({selectedUser.department})
                </span>
              </div>
              <h4 className="text-sm font-bold text-white mt-1 font-mono">
                3:00 AM Mass Data Staging & Removable USB Exfiltration
              </h4>
              <p className="text-xs text-slate-300 mt-0.5 font-mono">
                Diagnostics: Out-of-schedule authentication at {selectedUser.login_hour}:00 hrs, {selectedUser.files_accessed} files accessed, and {selectedUser.data_transfer_mb} MB buffered to USB.
              </p>
            </div>
          </div>

          <div className="text-right font-mono text-xs">
            <div className="text-slate-400 text-[10px]">DECISION VALUE</div>
            <div className="text-2xl font-black text-rose-400">{decisionFunction.toFixed(4)}</div>
          </div>
        </div>
      )}

      {/* 24-Hour Access Risk Matrix Chart & Monitored User Directory Table */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* 24-Hour User Access Matrix Chart */}
        <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-[#0b1222] p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center">
                <Clock className="w-4 h-4 mr-1.5" />
                24-Hour Enterprise Access Matrix
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
                Hourly authentication frequency highlighting authorized baseline vs off-hours outlier spikes.
              </p>
            </div>
            <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              Fleet Curve
            </span>
          </div>

          <UserAccessMatrixChart hourlyData={HOURLY_ACCESS_DATA} height={230} />

          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-2 border-t border-slate-800/80">
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-sm bg-emerald-400 inline-block" />
              <span>Core Business Hours (08:00 - 18:00)</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" />
              <span>High-Risk Off-Hours Spike</span>
            </div>
          </div>
        </div>

        {/* Monitored User Directory Table */}
        <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-[#0b1222] p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center">
                <Shield className="w-4 h-4 mr-1.5" />
                Active Directory Behavioral Queue
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
                Click any user profile to evaluate against the CERT Isolation Forest baseline.
              </p>
            </div>
            <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              Live Roster
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0e1628] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                <tr>
                  <th className="p-2.5">User Identity</th>
                  <th className="p-2.5">Shift / USB</th>
                  <th className="p-2.5">Data Volume</th>
                  <th className="p-2.5">Status</th>
                  <th className="p-2.5 text-right">Anomaly</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-[#090f1d]/50">
                {ENTERPRISE_USER_LIST.map((user) => {
                  const isSelected = selectedUser.user_id === user.user_id;
                  return (
                    <tr
                      key={user.user_id}
                      onClick={() => inspectUser(user)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="p-2.5">
                        <div className="font-bold text-white">{user.user_id}</div>
                        <div className="text-[10px] text-slate-400">{user.department}</div>
                      </td>
                      <td className="p-2.5">
                        <div className="text-slate-200">{String(user.login_hour).padStart(2, '0')}:00 hrs</div>
                        <div className="text-[10px]">
                          {user.usb_device_connected ? (
                            <span className="text-rose-400 font-bold">USB Active</span>
                          ) : (
                            <span className="text-slate-500">No Media</span>
                          )}
                        </div>
                      </td>
                      <td className="p-2.5">
                        <span className="text-slate-200 font-bold">{user.data_transfer_mb} MB</span>
                        <div className="text-[10px] text-slate-500">{user.files_accessed} files</div>
                      </td>
                      <td className="p-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          user.risk === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          user.risk === 'MEDIUM' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}>
                          {user.status}
                        </span>
                      </td>
                      <td className="p-2.5 text-right font-bold text-cyan-300">
                        {(user.anomaly_score * 100).toFixed(1)}%
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
