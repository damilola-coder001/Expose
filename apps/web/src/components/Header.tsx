"use client";

import { ThemeToggle } from "./ThemeToggle";
import { ShieldCheck } from "lucide-react";

interface HeaderProps {
  health?: { status?: string } | null;
  readiness?: { status?: string } | null;
  loading?: boolean;
  onRefreshHealth?: () => void;
  onOpenModal: (modal: "scope" | "privacy" | "terms" | "security") => void;
  onResetScan?: () => void;
  hasScanResult?: boolean;
  onOpenDomainVerify?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenModal,
  onResetScan,
  hasScanResult,
  onOpenDomainVerify,
}) => {
  return (
    <header className="w-full border-b border-slate-200 dark:border-[#1f2838] bg-white/90 dark:bg-[#0d1117]/90 backdrop-blur-sm sticky top-0 z-40 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
        {/* Left: Brand & Tag */}
        <div className="flex items-center gap-3">
          <button
            onClick={onResetScan}
            className="flex items-center gap-2.5 text-left focus:outline-none group"
            title="Expose Home"
          >
            <div className="w-6 h-6 rounded bg-slate-100 dark:bg-[#161f2e] border border-slate-300 dark:border-[#2c384d] flex items-center justify-center text-emerald-600 dark:text-emerald-400 font-mono text-xs font-bold group-hover:border-emerald-500/50 transition">
              E
            </div>
            <div className="flex items-baseline gap-2">
              <span className="font-bold text-sm tracking-wider text-slate-900 dark:text-slate-100 font-mono">
                EXPOSE
              </span>
              <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 hidden sm:inline">
                WIRE SECURITY INTELLIGENCE
              </span>
            </div>
          </button>
        </div>

        {/* Right: Technical Actions & Modals & Theme Toggle */}
        <div className="flex items-center gap-2 sm:gap-3 text-xs font-mono">
          {onOpenDomainVerify && (
            <button
              onClick={onOpenDomainVerify}
              className="px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800/80 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700 transition text-[11px] font-medium flex items-center gap-1.5 cursor-pointer"
              title="Verify Domain Ownership"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-500" />
              <span className="hidden sm:inline">Verify Domain</span>
            </button>
          )}

          <ThemeToggle />

          {hasScanResult && (
            <button
              onClick={onResetScan}
              className="px-2.5 py-1 rounded bg-emerald-50 dark:bg-[#162133] hover:bg-emerald-100 dark:hover:bg-[#1c2a42] text-emerald-700 dark:text-emerald-300 hover:text-emerald-800 dark:hover:text-emerald-200 border border-emerald-300 dark:border-emerald-500/30 transition text-[11px] font-medium"
            >
              New Audit
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
