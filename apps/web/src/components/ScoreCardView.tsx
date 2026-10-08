"use client";

import React from "react";
import { ScoreCard, RiskAssessment, CategoryScore } from "./types";
import { Shield, ShieldAlert, CheckCircle2, AlertTriangle, Info } from "lucide-react";

interface ScoreCardViewProps {
  scoreCard: ScoreCard;
  riskAssessment?: RiskAssessment;
  targetUrl: string;
  durationSeconds: number;
  scanId: string;
  domainVerified?: boolean;
  domainOwnershipProof?: string;
  onOpenVerifyModal?: () => void;
}

export const ScoreCardView: React.FC<ScoreCardViewProps> = ({
  scoreCard,
  riskAssessment,
  targetUrl,
  durationSeconds,
  scanId,
  domainVerified = false,
  domainOwnershipProof,
  onOpenVerifyModal,
}) => {
  const score = scoreCard.overall_score;
  const grade = scoreCard.letter_grade;

  const getScoreColor = (val: number) => {
    if (val >= 90) return "text-emerald-400 border-emerald-500/40 bg-emerald-950/20";
    if (val >= 75) return "text-cyan-400 border-cyan-500/40 bg-cyan-950/20";
    if (val >= 60) return "text-amber-400 border-amber-500/40 bg-amber-950/20";
    return "text-red-400 border-red-500/40 bg-red-950/20";
  };

  const getBarColor = (val: number) => {
    if (val >= 90) return "bg-emerald-500";
    if (val >= 75) return "bg-cyan-500";
    if (val >= 60) return "bg-amber-500";
    return "bg-red-500";
  };

  const categories = Object.entries(scoreCard.category_scores) as [string, CategoryScore][];

  return (
    <div className="w-full space-y-6">
      {/* Top Hero Posture Block */}
      <div className="bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] rounded-lg p-5 sm:p-6 shadow-sm dark:shadow-none transition-colors">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Left: Score Gauge Block (4 cols) */}
          <div className="lg:col-span-4 flex items-center gap-5 border-b lg:border-b-0 lg:border-r border-slate-200 dark:border-[#202735] pb-5 lg:pb-0 lg:pr-6">
            <div
              className={`w-24 h-24 rounded-lg border flex flex-col items-center justify-center shrink-0 tabular-nums ${getScoreColor(
                score
              )}`}
            >
              <span className="text-3xl font-extrabold font-mono text-slate-900 dark:text-slate-100 tracking-tight">
                {score}
              </span>
              <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 tracking-wider">
                / 100
              </span>
            </div>

            <div className="space-y-1.5 font-mono">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2 py-0.5 rounded text-xs font-bold bg-slate-100 dark:bg-[#16202f] border border-slate-300 dark:border-[#273750] text-slate-800 dark:text-slate-100">
                  GRADE {grade}
                </span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  {durationSeconds.toFixed(2)}s
                </span>
                {domainVerified ? (
                  <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                    <span>VERIFIED OWNER</span>
                  </span>
                ) : onOpenVerifyModal ? (
                  <button
                    type="button"
                    onClick={onOpenVerifyModal}
                    className="px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-600 dark:text-cyan-400 flex items-center gap-1 transition cursor-pointer"
                  >
                    <Shield className="w-3 h-3 text-cyan-500" />
                    <span>Verify Domain</span>
                  </button>
                ) : null}
              </div>
              <div className="text-xs text-slate-600 dark:text-slate-300">
                Flaws: <strong className="text-red-500 dark:text-red-400">{scoreCard.confirmed_flaws_count}</strong>
                <span className="mx-1.5 text-slate-400 dark:text-slate-600">•</span>
                Controls: <strong className="text-emerald-600 dark:text-emerald-400">{scoreCard.observed_properties_count}</strong>
              </div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 truncate max-w-[180px]">
                ID: {scanId}
              </div>
            </div>
          </div>

          {/* Right: Technical Posture Narrative (8 cols) */}
          <div className="lg:col-span-8 space-y-2.5 text-left">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-semibold text-sm text-slate-800 dark:text-slate-200 font-mono flex items-center gap-2">
                <span>SECURITY POSTURE EVALUATION</span>
              </h3>
              <span className="text-[10px] font-mono text-slate-500 uppercase">
                ENGINE {scoreCard.score_version || "v1.0"}
              </span>
            </div>

            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed font-sans">
              {riskAssessment?.posture_summary ||
                `Externally observable posture scored at ${score}/100 with ${scoreCard.confirmed_flaws_count} confirmed findings.`}
            </p>

            {riskAssessment?.critical_risks && riskAssessment.critical_risks.length > 0 && (
              <div className="p-2.5 rounded bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/40 text-red-700 dark:text-red-300 text-xs font-mono space-y-1">
                <div className="font-bold flex items-center gap-1.5 text-red-600 dark:text-red-400 text-[11px]">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>ACTION REQUIRED ({riskAssessment.critical_risks.length} URGENT ITEMS):</span>
                </div>
                {riskAssessment.critical_risks.map((crit, idx) => (
                  <div key={idx} className="text-[11px] text-slate-700 dark:text-slate-300 pl-5">
                    • {crit}
                  </div>
                ))}
              </div>
            )}

            <div className="text-[11px] text-slate-500 dark:text-slate-400 flex items-start gap-1.5 pt-1">
              <Info className="w-3.5 h-3.5 shrink-0 text-slate-400 dark:text-slate-400 mt-0.5" />
              <span>
                {scoreCard.score_philosophy ||
                  "This score reflects externally observable security controls and findings assessed by Expose. It is not an absolute warranty of security."}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 9 Canonical Categories Grid */}
      <div className="space-y-2 text-left">
        <div className="flex items-center justify-between px-1">
          <span className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300 tracking-wider">
            CANONICAL SECURITY CATEGORIES (WEIGHTED POSTURE)
          </span>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
            9 Domains · 100% Total Weight
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {categories.map(([catKey, cat]) => (
            <div
              key={catKey}
              className="bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] hover:border-slate-300 dark:hover:border-[#2c374c] rounded-lg p-3.5 flex flex-col justify-between transition shadow-sm dark:shadow-none"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <span className="text-xs font-mono font-medium text-slate-800 dark:text-slate-200 truncate" title={catKey}>
                    {catKey}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 shrink-0">
                    {cat.weight_percentage}% wt
                  </span>
                </div>

                <div className="flex items-baseline justify-between mb-2">
                  <span className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums">
                    {cat.score}
                    <span className="text-xs text-slate-500 dark:text-slate-400 font-normal"> / 100</span>
                  </span>
                  <span className="text-[11px] font-mono">
                    {cat.confirmed_issues_count > 0 ? (
                      <span className="text-red-600 dark:text-red-400 font-semibold">{cat.confirmed_issues_count} flaw(s)</span>
                    ) : (
                      <span className="text-emerald-600 dark:text-emerald-400 font-medium">0 flaws</span>
                    )}
                  </span>
                </div>

                {/* Progress bar */}
                <div className="w-full h-1.5 bg-slate-100 dark:bg-[#161d27] rounded-full overflow-hidden">
                  <div
                    className={`h-full ${getBarColor(cat.score)} transition-all duration-300`}
                    style={{ width: `${cat.score}%` }}
                  />
                </div>
              </div>

              <div className="mt-2.5 pt-2 border-t border-slate-100 dark:border-[#171e2a] flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400">
                <span>{cat.findings_count} total observations</span>
                <span>{cat.score >= 90 ? "OPTIMAL" : cat.score >= 70 ? "ACCEPTABLE" : "DEGRADED"}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
