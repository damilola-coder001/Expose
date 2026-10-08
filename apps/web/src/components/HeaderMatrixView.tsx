"use client";

import React, { useState } from "react";
import { HeaderTestResult, HeaderTestStatus } from "./types";

interface HeaderMatrixViewProps {
  matrix?: HeaderTestResult[];
  targetUrl?: string;
}

export const HeaderMatrixView: React.FC<HeaderMatrixViewProps> = ({ matrix = [], targetUrl = "" }) => {
  const [filter, setFilter] = useState<"ALL" | HeaderTestStatus>("ALL");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!matrix || matrix.length === 0) {
    return (
      <div className="bg-white dark:bg-[#111318] border border-slate-200 dark:border-[#1f242e] rounded-lg p-8 text-center shadow-sm dark:shadow-none">
        <p className="text-xs font-mono text-slate-500 dark:text-zinc-500 uppercase tracking-wider">
          No HTTP Security Header Test Matrix available for this target.
        </p>
      </div>
    );
  }

  const passCount = matrix.filter((t) => t.status === "PASS").length;
  const warnCount = matrix.filter((t) => t.status === "WARN").length;
  const failCount = matrix.filter((t) => t.status === "FAIL").length;
  const infoCount = matrix.filter((t) => t.status === "INFO").length;
  const passRate = matrix.length > 0 ? Math.round((passCount / matrix.length) * 100) : 0;

  const filteredTests = matrix.filter((t) => {
    if (filter === "ALL") return true;
    return t.status === filter;
  });

  const copyCommand = (id: string, cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getStatusBadge = (status: HeaderTestStatus) => {
    switch (status) {
      case "PASS":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400">
            PASS
          </span>
        );
      case "WARN":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-50 dark:bg-amber-950/60 border border-amber-300 dark:border-amber-800 text-amber-700 dark:text-amber-400">
            WARN
          </span>
        );
      case "FAIL":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-rose-50 dark:bg-rose-950/60 border border-rose-300 dark:border-rose-800 text-rose-700 dark:text-rose-400">
            FAIL
          </span>
        );
      case "INFO":
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-slate-100 dark:bg-zinc-800 border border-slate-300 dark:border-zinc-700 text-slate-700 dark:text-zinc-300">
            INFO
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Telemetry Summary Bar */}
      <div className="bg-white dark:bg-[#111318] border border-slate-200 dark:border-[#1f242e] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm dark:shadow-none">
        <div className="flex items-center gap-6">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 dark:text-zinc-500">Tests Evaluated</div>
            <div className="text-lg font-mono font-bold text-slate-900 dark:text-zinc-100">{matrix.length} Checks</div>
          </div>
          <div className="h-8 w-px bg-slate-200 dark:bg-zinc-800 hidden sm:block" />
          <div className="flex items-center gap-2">
            <span className="px-2 py-1 rounded bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800/60 text-emerald-700 dark:text-emerald-400 text-xs font-mono font-semibold">
              {passCount} PASS
            </span>
            <span className="px-2 py-1 rounded bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/60 text-amber-700 dark:text-amber-400 text-xs font-mono font-semibold">
              {warnCount} WARN
            </span>
            <span className="px-2 py-1 rounded bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800/60 text-rose-700 dark:text-rose-400 text-xs font-mono font-semibold">
              {failCount} FAIL
            </span>
            {infoCount > 0 && (
              <span className="px-2 py-1 rounded bg-slate-100 dark:bg-zinc-800 border border-slate-300 dark:border-zinc-700 text-slate-700 dark:text-zinc-400 text-xs font-mono font-semibold">
                {infoCount} INFO
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 dark:text-zinc-500">Compliance Rate</div>
            <div className="text-lg font-mono font-bold text-slate-900 dark:text-zinc-100">
              {passRate}%
            </div>
          </div>
        </div>
      </div>

      {/* Filter Navigation */}
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-[#1f242e] pb-3">
        <div className="flex items-center gap-2">
          {(["ALL", "FAIL", "WARN", "PASS"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                filter === f
                  ? "bg-slate-900 text-white dark:bg-zinc-800 dark:text-zinc-100 font-semibold shadow-xs"
                  : "text-slate-600 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-zinc-200 hover:bg-slate-100 dark:hover:bg-zinc-900"
              }`}
            >
              {f === "ALL" ? `All (${matrix.length})` : f === "FAIL" ? `Failures (${failCount})` : f === "WARN" ? `Warnings (${warnCount})` : `Passing (${passCount})`}
            </button>
          ))}
        </div>

        <div className="text-[11px] font-mono text-slate-500 dark:text-zinc-500 hidden md:block">
          Calibrated to Mozilla HTTP Observatory & MDN Web Security Guidelines
        </div>
      </div>

      {/* Test Matrix Table */}
      <div className="bg-white dark:bg-[#111318] border border-slate-200 dark:border-[#1f242e] rounded-lg overflow-hidden shadow-sm dark:shadow-none">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-[#1f242e] bg-slate-50 dark:bg-[#0c0e12] text-[10px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400">
                <th className="py-3 px-4 w-[32%]">Security Test & Specification</th>
                <th className="py-3 px-3 w-[12%] text-center">Verdict</th>
                <th className="py-3 px-4 w-[28%]">Observed on Wire</th>
                <th className="py-3 px-4 w-[28%]">Standard Expectation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-[#1f242e] text-xs">
              {filteredTests.map((test) => {
                const isExpanded = expandedId === test.id;
                const verifyCmd = test.header_name
                  ? `curl -sI ${targetUrl || "https://target.com"} | grep -i "${test.header_name.split(" ")[0]}"`
                  : `curl -sI ${targetUrl || "https://target.com"}`;

                return (
                  <React.Fragment key={test.id}>
                    <tr
                      onClick={() => setExpandedId(isExpanded ? null : test.id)}
                      className={`hover:bg-slate-50 dark:hover:bg-[#161a22] transition-colors cursor-pointer ${isExpanded ? "bg-slate-50/80 dark:bg-[#161a22]" : ""}`}
                    >
                      <td className="py-3.5 px-4">
                        <div className="font-medium text-slate-900 dark:text-zinc-200 flex items-center gap-2">
                          <span>{test.name}</span>
                          <span className="text-slate-400 dark:text-zinc-600 text-[10px]">({isExpanded ? "▲" : "▼"})</span>
                        </div>
                        {test.header_name && (
                          <div className="font-mono text-[11px] text-slate-500 dark:text-zinc-500 mt-0.5">
                            {test.header_name}
                          </div>
                        )}
                      </td>
                      <td className="py-3.5 px-3 text-center align-middle">
                        {getStatusBadge(test.status)}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px]">
                        {test.observed_value ? (
                          <span className="text-slate-800 dark:text-zinc-300 break-all line-clamp-2">
                            {test.observed_value}
                          </span>
                        ) : (
                          <span className="text-rose-600 dark:text-rose-400/80 italic font-sans text-xs">
                            Not Present (Missing header)
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-600 dark:text-zinc-400">
                        <span className="line-clamp-2">{test.expected_value}</span>
                      </td>
                    </tr>

                    {/* Detailed Drawer Row */}
                    {isExpanded && (
                      <tr className="bg-slate-50 dark:bg-[#0e1015] border-b border-slate-200 dark:border-[#1f242e]">
                        <td colSpan={4} className="p-4 space-y-3">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 dark:text-zinc-500 mb-1">
                                Technical Purpose & Vulnerability Context
                              </div>
                              <p className="text-xs text-slate-700 dark:text-zinc-300 leading-relaxed">
                                {test.description}
                              </p>
                            </div>
                            <div>
                              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 dark:text-zinc-500 mb-1">
                                Recommended Remediation
                              </div>
                              <p className="text-xs text-emerald-700 dark:text-emerald-300/90 leading-relaxed font-mono">
                                {test.advice}
                              </p>
                            </div>
                          </div>

                          {/* CLI Verification & Spec Links */}
                          <div className="pt-2 border-t border-slate-200 dark:border-[#1f242e] flex flex-wrap items-center justify-between gap-3">
                            <div className="flex items-center gap-2 flex-1 min-w-[280px]">
                              <span className="text-[10px] font-mono text-slate-500 dark:text-zinc-500 uppercase">Verify:</span>
                              <code className="px-2.5 py-1 rounded bg-slate-900 dark:bg-[#07080a] text-slate-100 dark:text-zinc-300 border border-slate-800 dark:border-zinc-800 text-[11px] font-mono flex-1 truncate">
                                {verifyCmd}
                              </code>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  copyCommand(test.id, verifyCmd);
                                }}
                                className="px-2.5 py-1 rounded text-[11px] font-mono bg-slate-200 hover:bg-slate-300 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-slate-800 dark:text-zinc-200 border border-slate-300 dark:border-zinc-700 transition-colors"
                              >
                                {copiedId === test.id ? "Copied!" : "Copy"}
                              </button>
                            </div>

                            {test.doc_url && (
                              <a
                                href={test.doc_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                className="inline-flex items-center gap-1.5 text-xs font-mono text-sky-600 dark:text-sky-400 hover:text-sky-700 dark:hover:text-sky-300 hover:underline"
                              >
                                <span>MDN Specification Documentation</span>
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                </svg>
                              </a>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

