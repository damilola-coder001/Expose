"use client";

import React, { useEffect } from "react";
import { X, ShieldAlert, FileText, Lock, CheckCircle2 } from "lucide-react";

export type ModalType = "scope" | "privacy" | "terms" | "security" | null;

interface LegalModalProps {
  type: ModalType;
  onClose: () => void;
}

export const LegalModal: React.FC<LegalModalProps> = ({ type, onClose }) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!type) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-2xl max-h-[85vh] bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] rounded-lg shadow-2xl flex flex-col text-left overflow-hidden">
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-200 dark:border-[#202735] flex items-center justify-between bg-slate-50 dark:bg-[#131923]">
          <div className="flex items-center gap-2.5">
            {type === "scope" && <ShieldAlert className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />}
            {type === "privacy" && <Lock className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />}
            {type === "terms" && <FileText className="w-4 h-4 text-amber-600 dark:text-amber-400" />}
            {type === "security" && <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />}
            <h2 className="font-semibold text-sm text-slate-900 dark:text-slate-100 font-mono uppercase tracking-wide">
              {type === "scope" && "Assessment Scope & Non-Assessed Boundaries"}
              {type === "privacy" && "Privacy & Telemetry Policy"}
              {type === "terms" && "Terms of Service & Acceptable Use"}
              {type === "security" && "Security & Responsible Disclosure"}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 hover:bg-slate-200 dark:hover:bg-[#1f2838] transition"
            title="Close (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-4 text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
          {type === "scope" && (
            <>
              <p className="font-medium text-slate-900 dark:text-slate-200">
                Expose performs strictly non-destructive, externally observable security audits from the perspective of an unauthenticated public visitor.
              </p>
              <div className="p-3.5 rounded bg-slate-50 dark:bg-[#131923] border border-slate-200 dark:border-[#202735] space-y-2 font-mono text-[11px]">
                <div className="font-bold text-slate-900 dark:text-slate-200">IN-SCOPE OBSERVATIONS:</div>
                <ul className="list-disc list-inside space-y-1 text-slate-700 dark:text-slate-300">
                  <li>DNS records (CAA, SPF, DMARC, DNSSEC presence)</li>
                  <li>TLS/SSL posture (Protocols 1.2/1.3, ciphers, certificate validation & SANs)</li>
                  <li>HTTP security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy)</li>
                  <li>Cookie attributes (Secure, HttpOnly, SameSite scopes)</li>
                  <li>Public HTML/JavaScript assets & Subresource Integrity (SRI)</li>
                  <li>Discovered endpoints, forms, and external third-party origins</li>
                </ul>
              </div>
              <div className="p-3.5 rounded bg-slate-50 dark:bg-[#131923] border border-slate-200 dark:border-[#202735] space-y-2 font-mono text-[11px]">
                <div className="font-bold text-slate-900 dark:text-slate-200">STRICTLY OUT-OF-SCOPE:</div>
                <ul className="list-disc list-inside space-y-1 text-slate-600 dark:text-slate-400">
                  <li>Credential brute-forcing or authenticated session tampering</li>
                  <li>Active code injection (SQLi, RCE, or payload fuzzing)</li>
                  <li>Denial of Service (DoS) or volumetric traffic floods</li>
                  <li>Private RFC1918 internal network discovery</li>
                  <li>Internal source code analysis or proprietary backend infrastructure</li>
                </ul>
              </div>
            </>
          )}

          {type === "privacy" && (
            <>
              <p className="font-medium text-slate-900 dark:text-slate-200">
                Expose is engineered with an evidence-first, ephemeral security model. We minimize persistent data storage to public technical telemetry.
              </p>
              <div className="space-y-3">
                <div>
                  <strong className="text-slate-900 dark:text-slate-200 block mb-1">1. Ephemeral Scanning Execution</strong>
                  <p className="text-slate-600 dark:text-slate-400">
                    HTTP requests issued during an audit only request publicly reachable web resources. We never store personal identity information, passwords, or authenticated token bodies.
                  </p>
                </div>
                <div>
                  <strong className="text-slate-900 dark:text-slate-200 block mb-1">2. Technical Evidence Retention</strong>
                  <p className="text-slate-600 dark:text-slate-400">
                    Captured wire headers, TLS certificate parameters, and DNS responses are stored strictly to verify security posture and allow the target owner to review empirical remediation proof.
                  </p>
                </div>
                <div>
                  <strong className="text-slate-900 dark:text-slate-200 block mb-1">3. Zero Third-Party Tracker Selling</strong>
                  <p className="text-slate-600 dark:text-slate-400">
                    Audit results are not commercialized or sold to third-party ad networks.
                  </p>
                </div>
              </div>
            </>
          )}

          {type === "terms" && (
            <>
              <p className="font-medium text-slate-900 dark:text-slate-200">
                By utilizing the Expose security platform, you agree to adhere to our strict authorization policy.
              </p>
              <div className="space-y-3">
                <div>
                  <strong className="text-slate-900 dark:text-slate-200 block mb-1">1. Mandatory Authorization</strong>
                  <p className="text-slate-600 dark:text-slate-400">
                    You must only scan websites that you own or have obtained explicit authorization to audit. You assume full legal responsibility for any domain queries submitted.
                  </p>
                </div>
                <div>
                  <strong className="text-slate-900 dark:text-slate-200 block mb-1">2. Non-Destructive Operation</strong>
                  <p className="text-slate-600 dark:text-slate-400">
                    Expose is built strictly for defensive observation. Automated high-frequency scraping or intentional attempts to bypass rate limits are prohibited.
                  </p>
                </div>
                <div>
                  <strong className="text-slate-900 dark:text-slate-200 block mb-1">3. Non-Warranty Disclaimer</strong>
                  <p className="text-slate-600 dark:text-slate-400">
                    Expose evaluates externally observable configurations. A score of 100/100 does not guarantee that a target is free from internal logic flaws or zero-day vulnerabilities.
                  </p>
                </div>
              </div>
            </>
          )}

          {type === "security" && (
            <>
              <p className="font-medium text-slate-900 dark:text-slate-200">
                We believe in responsible disclosure and transparent security research.
              </p>
              <div className="space-y-3">
                <div>
                  <strong className="text-slate-900 dark:text-slate-200 block mb-1">Security Contact</strong>
                  <p className="text-slate-600 dark:text-slate-400">
                    If you identify a vulnerability in the Expose scanner engine or API gateway, please submit technical evidence directly to the engineering team.
                  </p>
                </div>
                <div className="p-3 rounded bg-slate-50 dark:bg-[#131923] border border-slate-200 dark:border-[#202735] font-mono text-[11px] text-slate-700 dark:text-slate-300">
                  Contact: <span className="text-emerald-600 dark:text-emerald-400 font-semibold">security@expose.local</span>
                  <br />
                  Encryption: PGP key available upon request
                  <br />
                  SLA: Initial response within 24 business hours
                </div>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-200 dark:border-[#202735] bg-slate-50 dark:bg-[#131923] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-slate-200 hover:bg-slate-300 dark:bg-[#1f2838] dark:hover:bg-[#273245] text-slate-800 dark:text-slate-200 text-xs font-mono transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
