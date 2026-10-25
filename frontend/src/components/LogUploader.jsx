import React, { useState, useRef } from 'react';
import { UploadCloud, FileSpreadsheet, CheckCircle2, AlertTriangle, ArrowRight, Loader2, Download, Table } from 'lucide-react';

export default function LogUploader({ moduleTitle, onUploadBatch, sampleCsvData, sampleFileName = 'telemetry.csv' }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [batchResults, setBatchResults] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const inputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleFileSelected(e.target.files[0]);
    }
  };

  const handleFileSelected = (file) => {
    if (!file.name.endsWith('.csv')) {
      setErrorMsg('Please upload a valid .csv file format.');
      return;
    }
    setErrorMsg(null);
    setSelectedFile(file);
    setBatchResults(null);
  };

  const handleProcessUpload = async () => {
    if (!selectedFile) return;
    setIsProcessing(true);
    setErrorMsg(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      const res = await onUploadBatch(formData);
      setBatchResults(res.batch_summary);
    } catch (err) {
      console.error('Batch upload error:', err);
      setErrorMsg(err?.response?.data?.message || err?.message || 'Failed to process batch CSV.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDownloadSample = () => {
    if (!sampleCsvData) return;
    const blob = new Blob([sampleCsvData], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', sampleFileName);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-4">
      {/* Upload Box */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`relative p-6 rounded-xl border-2 border-dashed transition-all text-center ${
          dragActive
            ? 'border-cyan-400 bg-cyan-950/30'
            : selectedFile
            ? 'border-emerald-500/50 bg-[#0d1627]'
            : 'border-slate-800 bg-[#0d1526]/60 hover:border-slate-700'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv"
          onChange={handleChange}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-3">
          <div className="p-3 rounded-full bg-slate-900 border border-slate-800 text-cyan-400">
            {selectedFile ? (
              <FileSpreadsheet className="w-7 h-7 text-emerald-400" />
            ) : (
              <UploadCloud className="w-7 h-7 text-cyan-400" />
            )}
          </div>

          <div>
            <p className="text-sm font-medium text-slate-200">
              {selectedFile ? selectedFile.name : `Upload batch CSV for ${moduleTitle}`}
            </p>
            <p className="text-xs text-slate-400 mt-1">
              {selectedFile
                ? `${(selectedFile.size / 1024).toFixed(1)} KB — Ready to analyze`
                : 'Drag and drop your telemetry CSV file here, or click to browse'}
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
            <button
              type="button"
              onClick={() => inputRef.current?.click()}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 transition"
            >
              Browse Files
            </button>

            {sampleCsvData && (
              <button
                type="button"
                onClick={handleDownloadSample}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 text-xs font-mono text-cyan-300 border border-cyan-800/50 transition"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Sample CSV</span>
              </button>
            )}

            {selectedFile && (
              <button
                type="button"
                onClick={handleProcessUpload}
                disabled={isProcessing}
                className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold shadow-lg shadow-cyan-950 transition disabled:opacity-50"
              >
                {isProcessing ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing Batch...</span>
                  </>
                ) : (
                  <>
                    <span>Run Batch Inference</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/60 text-xs font-mono text-rose-300 flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Batch Summary Stats & Table */}
      {batchResults && (
        <div className="rounded-xl border border-slate-800 bg-[#0b1322] p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <h5 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center">
              <Table className="w-4 h-4 mr-1.5" />
              Batch Inspection Results Summary
            </h5>
            <span className="text-xs font-mono text-slate-400">
              Processed: <strong className="text-white">{batchResults.total_records}</strong> records
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-slate-400 text-[10px]">TOTAL ANALYZED</div>
              <div className="text-lg font-bold text-white mt-1">{batchResults.total_records}</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-slate-400 text-[10px]">ANOMALIES DETECTED</div>
              <div className="text-lg font-bold text-rose-400 mt-1">
                {batchResults.anomalies_detected ?? batchResults.threats_detected ?? 0}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-slate-400 text-[10px]">ANOMALY RATE</div>
              <div className="text-lg font-bold text-amber-400 mt-1">
                {batchResults.anomaly_rate_percent ?? batchResults.threat_rate_percent ?? 0}%
              </div>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-slate-400 text-[10px]">MAX RISK SCORE</div>
              <div className="text-lg font-bold text-cyan-400 mt-1">
                {((batchResults.max_composite_score ?? batchResults.max_threat_probability ?? batchResults.max_anomaly_score ?? 0) * 100).toFixed(1)}%
              </div>
            </div>
          </div>

          {/* Records Table Preview */}
          {batchResults.records && batchResults.records.length > 0 && (
            <div className="max-h-56 overflow-y-auto border border-slate-800 rounded-lg">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-900/90 text-slate-400 text-[10px] sticky top-0 uppercase border-b border-slate-800">
                  <tr>
                    <th className="p-2.5">#</th>
                    <th className="p-2.5">Identifier</th>
                    <th className="p-2.5">Risk Level</th>
                    <th className="p-2.5">Score</th>
                    <th className="p-2.5">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                  {batchResults.records.slice(0, 15).map((row, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/40 transition">
                      <td className="p-2.5 text-slate-500">{row.row_index ?? idx + 1}</td>
                      <td className="p-2.5 text-slate-200">
                        {row.processId ? `PID ${row.processId}` : row.protocol ? `${row.protocol.toUpperCase()} / ${row.service}` : row.user_id}
                      </td>
                      <td className="p-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          row.risk_level === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                          row.risk_level === 'HIGH' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                          'bg-slate-800 text-slate-300'
                        }`}>
                          {row.risk_level}
                        </span>
                      </td>
                      <td className="p-2.5 text-cyan-300">
                        {(((row.composite_score ?? row.threat_probability ?? row.anomaly_score) || 0) * 100).toFixed(1)}%
                      </td>
                      <td className="p-2.5">
                        {(row.is_anomaly || row.threat_detected === 1) ? (
                          <span className="text-rose-400 font-bold flex items-center">
                            <AlertTriangle className="w-3 h-3 mr-1" /> Anomaly
                          </span>
                        ) : (
                          <span className="text-emerald-400 flex items-center">
                            <CheckCircle2 className="w-3 h-3 mr-1" /> Normal
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

