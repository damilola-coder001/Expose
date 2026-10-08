"use client";

import React, { useState } from "react";
import { Finding, SeverityLevel } from "./types";
import {
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Zap,
  ExternalLink,
  Terminal,
  FileCode,
  ShieldCheck,
  AlertOctagon,
  AlertTriangle,
  Info,
} from "lucide-react";

interface FindingItemProps {
  finding: Finding;
  onVerifyFix: (findingId: string) => Promise<void>;
  isVerifying: boolean;
  verificationFeedback?: { success: boolean; message: string };
}

export const FindingItem: React.FC<FindingItemProps> = ({
  finding,
  onVerifyFix,
  isVerifying,
  verificationFeedback,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-red-600 text-white font-bold";
      case "HIGH":
        return "bg-red-50 dark:bg-red-950/60 border border-red-300 dark:border-red-500/50 text-red-700 dark:text-red-400 font-bold";
      case "MEDIUM":
        return "bg-amber-50 dark:bg-amber-950/60 border border-amber-300 dark:border-amber-500/50 text-amber-800 dark:text-amber-300 font-bold";
      case "LOW":
        return "bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-300 dark:border-cyan-500/50 text-cyan-800 dark:text-cyan-300 font-medium";
      case "INFO":
      default:
        return "bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-normal";
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "FIXED":
        return "text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-500/40 font-semibold";
      case "CONFIRMED":
        return "text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-950/40 border border-red-300 dark:border-red-900/40 font-medium";
      case "OBSERVED":
        return "text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-800";
      default:
        return "text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-800";
    }
  };

  const remediationText =
    finding.recommendation && typeof finding.recommendation === "object"
      ? finding.recommendation.remediation
      : typeof finding.recommendation === "string"
      ? finding.recommendation
      : finding.remediation || "Review and update security configuration according to advisory.";

  const configSnippet =
    finding.recommendation && typeof finding.recommendation === "object"
      ? finding.recommendation.config_snippet
      : null;

  const cliCommand =
    finding.verification?.command || finding.verification_command || "";

  const cliTool =
    finding.verification?.tool || (cliCommand.includes("openssl") ? "openssl" : cliCommand.includes("dig") ? "dig" : "curl");

  const impactText =
    finding.impact_explanation || finding.impact || finding.description;

  const handleCopyCli = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!cliCommand) return;
    navigator.clipboard.writeText(cliCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] hover:border-slate-300 dark:hover:border-[#2d374b] rounded-lg transition overflow-hidden text-left shadow-sm dark:shadow-none">
      {/* Finding Summary Header Row */}
      <div
        onClick={() => setIsExpanded(!isExpanded)}
        className="p-3.5 sm:p-4 cursor-pointer flex items-start justify-between gap-4 select-none"
      >
        <div className="space-y-1.5 flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap font-mono text-[10px]">
            {/* Severity Pill */}
            <span className={`px-2 py-0.5 rounded tracking-wide ${getSeverityBadge(finding.severity)}`}>
              {finding.severity}
            </span>

            {/* Status Pill */}
            <span className={`px-2 py-0.5 rounded ${getStatusBadge(finding.status)}`}>
              {finding.status}
            </span>

            {/* Category Tag */}
            <span className="text-slate-600 dark:text-slate-400 px-1.5 py-0.5 bg-slate-100 dark:bg-[#131923] border border-slate-200 dark:border-[#202735] rounded font-medium">
              {finding.category}
            </span>

            {/* Standards Mapping */}
            {finding.owasp_top10 && (
              <span className="text-purple-700 dark:text-purple-300 px-1.5 py-0.5 bg-purple-50 dark:bg-purple-950/40 border border-purple-200 dark:border-purple-800/40 rounded font-medium">
                {finding.owasp_top10.split(" - ")[0]}
              </span>
            )}

            {finding.owasp_asvs && (
              <span className="text-amber-800 dark:text-amber-300 px-1.5 py-0.5 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/40 rounded font-medium">
                ASVS {finding.owasp_asvs}
              </span>
            )}

            {(finding.cwe_id || finding.cwe) && (
              <span className="text-cyan-800 dark:text-cyan-300 px-1.5 py-0.5 bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-200 dark:border-cyan-800/40 rounded font-medium">
                {finding.cwe_id || finding.cwe}
              </span>
            )}
          </div>

          <h4 className="font-semibold text-sm text-slate-900 dark:text-slate-100 font-sans tracking-tight">
            {finding.title}
          </h4>

          <p className="text-xs text-slate-600 dark:text-slate-400 font-sans line-clamp-1">
            {finding.description}
          </p>
        </div>

        {/* Right side: Rule ID & Accordion Chevron */}
        <div className="flex items-center gap-3 shrink-0 text-slate-400 pt-1">
          {finding.rule_id && (
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-500 hidden md:inline">
              {finding.rule_id}
            </span>
          )}
          {isExpanded ? (
            <ChevronUp className="w-4 h-4 text-slate-700 dark:text-slate-300" />
          ) : (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          )}
        </div>
      </div>

      {/* Expanded Technical Dossier */}
      {isExpanded && (
        <div className="p-4 sm:p-5 bg-slate-50 dark:bg-[#090b0e] border-t border-slate-200 dark:border-[#202735] space-y-4 text-xs font-sans">
          {/* Top Action Bar: Re-verify on wire */}
          <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-slate-200 dark:border-[#18202d]">
            <div className="text-[11px] font-mono text-slate-600 dark:text-slate-400">
              Deterministic Rule: <span className="text-slate-900 dark:text-slate-200 font-medium">{finding.rule_id || "OBS-001"}</span>
              <span className="mx-2 text-slate-300 dark:text-slate-700">|</span>
              Confidence: <span className="text-slate-900 dark:text-slate-200 font-medium">{finding.confidence}</span>
            </div>

            <div>
              {finding.status !== "FIXED" ? (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onVerifyFix(finding.id);
                  }}
                  disabled={isVerifying}
                  className="px-3 py-1 rounded bg-emerald-50 hover:bg-emerald-100 dark:bg-[#132018] dark:hover:bg-[#1a2e22] text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-500/40 text-xs font-mono font-medium transition flex items-center gap-1.5 shadow-xs"
                  title="Issue fresh targeted probe against the target to verify if this issue has been resolved"
                >
                  <Zap className={`w-3.5 h-3.5 ${isVerifying ? "animate-spin text-emerald-600 dark:text-emerald-400" : ""}`} />
                  <span>{isVerifying ? "Verifying on Wire..." : "Verify Fix on Wire"}</span>
                </button>
              ) : (
                <span className="px-2.5 py-1 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-500/40 text-xs font-mono font-bold flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Verified Fixed</span>
                </span>
              )}
            </div>
          </div>

          {/* Verification feedback message */}
          {verificationFeedback && (
            <div
              className={`p-3 rounded text-xs font-mono border ${
                verificationFeedback.success
                  ? "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-300 dark:border-emerald-500/40 text-emerald-800 dark:text-emerald-300"
                  : "bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-500/40 text-amber-800 dark:text-amber-300"
              }`}
            >
              {verificationFeedback.message}
            </div>
          )}

          {/* 1. Observation & Technical Summary */}
          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-600 dark:text-slate-400 font-semibold block">
              Observed Technical State
            </span>
            <p className="text-slate-800 dark:text-slate-200 leading-relaxed bg-white dark:bg-[#0e131a] border border-slate-200 dark:border-[#1b2230] p-3 rounded">
              {finding.description}
            </p>
          </div>

          {/* 2. Risk & Impact Rationale */}
          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-600 dark:text-slate-400 font-semibold block">
              Risk &amp; Exposure Rationale
            </span>
            <p className="text-slate-700 dark:text-slate-300 leading-relaxed bg-white dark:bg-[#0e131a] border border-slate-200 dark:border-[#1b2230] p-3 rounded">
              {impactText}
            </p>
          </div>

          {/* 3. Recommended Remediation */}
          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-700 dark:text-emerald-400 font-semibold block">
              Recommended Remediation
            </span>
            <div className="p-3.5 rounded bg-white dark:bg-[#0e131a] border border-slate-200 dark:border-[#1b2230] space-y-2">
              <p className="text-slate-800 dark:text-slate-200 leading-relaxed">{remediationText}</p>
              {configSnippet && (
                <div className="mt-2">
                  <div className="text-[10px] font-mono text-slate-500 mb-1">Configuration Snippet:</div>
                  <pre className="p-2.5 rounded bg-slate-900 dark:bg-[#07090c] border border-slate-800 dark:border-[#18202d] text-[11px] font-mono text-emerald-400 dark:text-emerald-300 overflow-x-auto">
                    {configSnippet}
                  </pre>
                </div>
              )}
            </div>
          </div>

          {/* 4. Independent CLI Verification Command */}
          {cliCommand && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-[10px] font-mono text-slate-600 dark:text-slate-400">
                <span className="font-semibold uppercase tracking-wider">
                  Independent Reproducible Verification ({cliTool.toUpperCase()}):
                </span>
                <span>Run in terminal</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-white dark:bg-[#0e131a] border border-slate-200 dark:border-[#1b2230] font-mono text-xs text-cyan-800 dark:text-cyan-300">
                <span className="truncate pr-3 selection:bg-cyan-500/20">{cliCommand}</span>
                <button
                  onClick={handleCopyCli}
                  className="p-1.5 rounded bg-slate-100 hover:bg-slate-200 dark:bg-[#161d27] dark:hover:bg-[#202937] text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white border border-slate-300 dark:border-[#273243] transition shrink-0"
                  title="Copy command"
                >
                  {copied ? (
                    <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            </div>
          )}

          {/* 5. Verifiable Technical Wire Evidence */}
          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-600 dark:text-slate-400 font-semibold block">
              Raw Empirical Evidence ({finding.evidence.type})
            </span>
            <div className="p-3 rounded bg-white dark:bg-[#0e131a] border border-slate-200 dark:border-[#1b2230] font-mono text-[11px] space-y-2">
              <div className="text-slate-800 dark:text-slate-300">
                <span className="text-slate-500 dark:text-slate-400 font-semibold">Summary:</span> {finding.evidence.summary}
              </div>

              {finding.evidence.response_headers && Object.keys(finding.evidence.response_headers).length > 0 && (
                <div className="pt-2 border-t border-slate-200 dark:border-[#171e2a] space-y-1">
                  <span className="text-slate-600 dark:text-slate-400 font-semibold block">Observed Response Headers:</span>
                  <div className="grid grid-cols-1 gap-1 max-h-40 overflow-y-auto pr-1">
                    {Object.entries(finding.evidence.response_headers).map(([hk, hv]) => (
                      <div key={hk} className="text-slate-800 dark:text-slate-300 flex">
                        <span className="text-slate-500 dark:text-slate-400 min-w-[160px] truncate">{hk}:</span>
                        <span className="text-slate-800 dark:text-slate-300 break-all">{hv}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {finding.evidence.raw_data && Object.keys(finding.evidence.raw_data).length > 0 && (
                <div className="pt-2 border-t border-slate-200 dark:border-[#171e2a]">
                  <span className="text-slate-600 dark:text-slate-400 font-semibold block mb-1">Raw Observations JSON:</span>
                  <pre className="p-2 rounded bg-slate-900 dark:bg-[#07090c] border border-slate-800 dark:border-[#161d28] text-slate-200 dark:text-slate-300 overflow-x-auto text-[10px] max-h-48 overflow-y-auto">
                    {JSON.stringify(finding.evidence.raw_data, null, 2)}
                  </pre>
                </div>
              )}

              <div className="pt-1 text-[10px] text-slate-500 dark:text-slate-400 border-t border-slate-200 dark:border-[#171e2a]">
                Captured Wire Timestamp: {finding.evidence.timestamp || finding.timestamp || "Live Capture"}
              </div>
            </div>
          </div>

          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <div className="pt-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-600 dark:text-slate-400 font-semibold block mb-1.5">
                Authoritative References
              </span>
              <div className="flex flex-wrap gap-2">
                {finding.references.map((ref, idx) => (
                  <a
                    key={idx}
                    href={ref.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[11px] font-mono text-cyan-700 dark:text-cyan-400 hover:text-cyan-800 dark:hover:text-cyan-300 flex items-center gap-1 bg-cyan-50 dark:bg-[#101722] border border-cyan-200 dark:border-[#1f2c3f] px-2 py-0.5 rounded transition"
                  >
                    <span>{ref.name || "Advisory Reference"}</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
