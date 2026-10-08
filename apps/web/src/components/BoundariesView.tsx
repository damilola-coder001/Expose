"use client";

import React from "react";
import { NotAssessedArea } from "./types";
import { ShieldAlert, AlertCircle, CheckCircle2 } from "lucide-react";

interface BoundariesViewProps {
  boundaries?: NotAssessedArea[];
}

export const BoundariesView: React.FC<BoundariesViewProps> = ({ boundaries }) => {
  const defaultBoundaries: NotAssessedArea[] = [
    {
      area: "Authentication & Session Workflows",
      reason: "Requires authenticated credentials, test accounts, and active session tokens.",
      explanation:
        "External unauthenticated scanning cannot evaluate password complexity enforcement, credential stuffing defenses, MFA workflows, or session token invalidation upon logout.",
    },
    {
      area: "Business Logic & Workflow Integrity",
      reason: "Requires contextual knowledge of business workflows, transaction logic, and multi-tenant authorization matrices.",
      explanation:
        "Logic flaws such as Insecure Direct Object References (IDOR), price/quantity tampering, and race conditions cannot be reliably assessed from passive external surface analysis.",
    },
    {
      area: "Active Code Injection (SQLi, RCE, Command Fuzzing)",
      reason: "Invasive attack payloads are strictly prohibited in safe external intelligence assessments.",
      explanation:
        "Expose operates safely without sending destructive or intrusive payloads. Active exploit testing requires explicit written rules of engagement and dedicated penetration testing.",
    },
    {
      area: "Internal Infrastructure & Private VPCs",
      reason: "Protected behind edge firewalls, NAT gateways, and private network segmentation.",
      explanation:
        "Internal microservices, private databases, backend APIs, and cloud metadata services cannot be directly queried from the public internet.",
    },
    {
      area: "Source Code & Repository Dependencies",
      reason: "Requires direct access to source code repositories, lockfiles, and CI/CD pipelines.",
      explanation:
        "Public web endpoints only expose runtime wire responses, not underlying Git repository source code or build pipeline artifacts.",
    },
  ];

  const items = boundaries && boundaries.length > 0 ? boundaries : defaultBoundaries;

  return (
    <div className="space-y-4 text-left">
      <div className="p-4 rounded-lg bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] flex items-start gap-3 text-xs shadow-sm dark:shadow-none">
        <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1 font-sans">
          <strong className="text-slate-900 dark:text-slate-200 block font-mono text-xs">
            Explicit Security Assessment Scope &amp; Boundaries
          </strong>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            Expose evaluates externally observable configurations from the viewpoint of an external observer.
            To maintain technical rigor and eliminate false assumptions, the following 5 domains are explicitly declared as outside the scope of an external unauthenticated audit.
          </p>
        </div>
      </div>

      <div className="space-y-3">
        {items.map((item, idx) => (
          <div
            key={idx}
            className="p-4 rounded-lg bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] space-y-2 font-sans text-xs shadow-sm dark:shadow-none"
          >
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h4 className="font-semibold text-sm text-slate-900 dark:text-slate-100 font-mono flex items-center gap-2">
                <span className="w-5 h-5 rounded bg-slate-100 dark:bg-[#16202e] border border-slate-300 dark:border-[#26354c] text-amber-700 dark:text-amber-400 text-xs font-mono font-bold flex items-center justify-center shrink-0">
                  {idx + 1}
                </span>
                <span>{item.area}</span>
              </h4>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800/40 font-medium">
                OUT OF SCOPE
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1 text-slate-700 dark:text-slate-300 font-sans">
              <div className="p-3 rounded bg-slate-50 dark:bg-[#090b0e] border border-slate-200 dark:border-[#1b2230]">
                <strong className="text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-slate-400 block mb-1">
                  Why It Cannot Be Assessed:
                </strong>
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{item.reason}</p>
              </div>

              <div className="p-3 rounded bg-slate-50 dark:bg-[#090b0e] border border-slate-200 dark:border-[#1b2230]">
                <strong className="text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-slate-400 block mb-1">
                  Requirements for Assessment:
                </strong>
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{item.explanation}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
