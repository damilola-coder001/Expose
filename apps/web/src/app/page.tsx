"use client";

import React, { useState, useEffect } from "react";
import { Header } from "../components/Header";
import { LegalModal, ModalType } from "../components/LegalModal";
import { DomainVerificationModal } from "../components/DomainVerificationModal";
import { ScoreCardView } from "../components/ScoreCardView";
import { FindingItem } from "../components/FindingItem";
import { AttackSurfaceView } from "../components/AttackSurfaceView";
import { HeaderMatrixView } from "../components/HeaderMatrixView";
import { ScanResult, Finding, SeverityLevel } from "../components/types";
import {
  Globe,
  ArrowRight,
  RefreshCw,
  AlertTriangle,
  Shield,
  Layers,
  Search,
  Download,
  Copy,
  Check,
  CheckCircle2,
  FileText,
  TableProperties,
} from "lucide-react";

export default function HomePage() {
  const [health, setHealth] = useState<any>(null);
  const [readiness, setReadiness] = useState<any>(null);
  const [loadingHealth, setLoadingHealth] = useState(true);

  // Target & scan state
  const [targetUrl, setTargetUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [scanTimer, setScanTimer] = useState(0);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // UI state
  const [activeTab, setActiveTab] = useState<"FINDINGS" | "MATRIX" | "ATTACK_SURFACE">("FINDINGS");
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [searchFilter, setSearchFilter] = useState<string>("");
  const [activeModal, setActiveModal] = useState<ModalType>(null);
  const [isDomainModalOpen, setIsDomainModalOpen] = useState(false);
  const [verifyingFindingId, setVerifyingFindingId] = useState<string | null>(null);
  const [verificationFeedback, setVerificationFeedback] = useState<Record<string, { success: boolean; message: string }>>({});
  const [copiedSummary, setCopiedSummary] = useState(false);

  // Scan simulation steps for informative loading
  const scanStages = [
    "Resolving DNS records and network transport...",
    "Inspecting TLS certificates, protocols, and cipher suites...",
    "Auditing HTTP security headers, HSTS, and frame protection...",
    "Evaluating cookie attributes, flags, and session scopes...",
    "Enumerating client-side attack surface and external origins...",
    "Computing deterministic 0-100 scorecard and verified findings...",
  ];

  const fetchStatus = async () => {
    setLoadingHealth(true);
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
    try {
      const [hRes, rRes] = await Promise.allSettled([
        fetch(`${apiUrl}/health`),
        fetch(`${apiUrl}/ready`),
      ]);

      if (hRes.status === "fulfilled" && hRes.value.ok) {
        setHealth(await hRes.value.json());
      } else {
        setHealth({ status: "DOWN" });
      }

      if (rRes.status === "fulfilled" && rRes.value.ok) {
        setReadiness(await rRes.value.json());
      } else {
        setReadiness({ status: "DOWN" });
      }
    } catch {
      setHealth({ status: "DOWN" });
      setReadiness({ status: "DOWN" });
    } finally {
      setLoadingHealth(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  // Timer & stage progression during scan
  useEffect(() => {
    let tInterval: any;
    let sInterval: any;
    if (scanning) {
      setScanTimer(0);
      setScanStep(0);
      tInterval = setInterval(() => {
        setScanTimer((prev) => prev + 0.1);
      }, 100);
      sInterval = setInterval(() => {
        setScanStep((prev) => (prev < scanStages.length - 1 ? prev + 1 : prev));
      }, 900);
    }
    return () => {
      clearInterval(tInterval);
      clearInterval(sInterval);
    };
  }, [scanning]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl || !authorized || scanning) return;

    setScanning(true);
    setScanError(null);
    setScanResult(null);
    setVerificationFeedback({});

    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";

    try {
      const res = await fetch(`${apiUrl}/api/v1/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: targetUrl.trim(),
          authorized: true,
          allow_private: false,
        }),
      });

      const contentType = res.headers.get("content-type") || "";
      let data: any = null;

      if (contentType.includes("application/json")) {
        try {
          data = await res.json();
        } catch {
          data = null;
        }
      } else {
        const text = await res.text();
        if (text) {
          // Discard raw HTML bodies (e.g. gateway 502/504 pages) so clean error messages are shown
          if (text.trim().startsWith("<") || text.includes("<!DOCTYPE")) {
            data = null;
          } else {
            data = { detail: text };
          }
        }
      }

      if (!res.ok) {
        let errorMsg = "Audit execution failed";
        const hasTextDetail = data?.detail && typeof data.detail === "string" && !data.detail.trim().startsWith("<");
        if (res.status === 429) {
          errorMsg = hasTextDetail ? data.detail : "Rate limit reached: Please wait 10 seconds before running another scan.";
        } else if (res.status === 502 || res.status === 503 || res.status === 504 || res.status === 500) {
          errorMsg = hasTextDetail ? data.detail : "Security engine or target took too long to respond. Please verify the target is reachable and try again.";
        } else if (hasTextDetail) {
          errorMsg = data.detail;
        } else if (data?.error?.message) {
          errorMsg = data.error.message;
        } else if (data?.message) {
          errorMsg = data.message;
        }
        setScanError(errorMsg);
      } else {
        if (data) {
          setScanResult(data);
          setActiveTab("FINDINGS");
        } else {
          setScanError("Received an empty response from the analysis engine.");
        }
      }
    } catch (err: any) {
      setScanError(err.message || "Unable to reach security analysis engine. Please verify the target is reachable.");
    } finally {
      setScanning(false);
    }
  };

  const handleVerifyFix = async (findingId: string) => {
    if (!scanResult) return;
    setVerifyingFindingId(findingId);
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
    try {
      const scanId = scanResult.id || (scanResult as any).scan_id;
      const res = await fetch(`${apiUrl}/scans/${scanId}/findings/${findingId}/verify`, {
        method: "POST",
      });
      const contentType = res.headers.get("content-type") || "";
      let data: any = null;
      if (contentType.includes("application/json")) {
        data = await res.json();
      } else {
        const text = await res.text();
        data = { detail: text };
      }
      if (!res.ok) throw new Error(data?.detail || "Verification check failed");

      if (data.status === "FIXED") {
        setVerificationFeedback((prev) => ({
          ...prev,
          [findingId]: {
            success: true,
            message: `✓ Fix Verified on wire! Posture score updated from ${data.score_before} to ${data.score_after}`,
          },
        }));

        setScanResult((prev) => {
          if (!prev) return prev;
          const updatedFindings = prev.findings.map((f) =>
            f.id === findingId ? { ...f, status: "FIXED" as const } : f
          );
          const updatedScore = prev.score_card
            ? {
                ...prev.score_card,
                overall_score: data.score_after,
                confirmed_flaws_count: Math.max(0, prev.score_card.confirmed_flaws_count - 1),
                observed_properties_count: prev.score_card.observed_properties_count + 1,
              }
            : undefined;

          return {
            ...prev,
            findings: updatedFindings,
            score_card: updatedScore as any,
          };
        });
      } else {
        setVerificationFeedback((prev) => ({
          ...prev,
          [findingId]: {
            success: false,
            message: `⚠️ Finding persists on target: ${data.message}`,
          },
        }));
      }
    } catch (err: any) {
      setVerificationFeedback((prev) => ({
        ...prev,
        [findingId]: {
          success: false,
          message: `Verification Error: ${err.message}`,
        },
      }));
    } finally {
      setVerifyingFindingId(null);
    }
  };

  const handleExportJson = () => {
    if (!scanResult) return;
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `expose-audit-${scanResult.id || (scanResult as any).scan_id || "report"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportHtml = () => {
    if (!scanResult) return;
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
    const scanId = scanResult.id || (scanResult as any).scan_id || "report";
    window.open(`${apiUrl}/api/v1/scans/${scanId}/export/html`, "_blank");
  };

  const handleCopySummary = () => {
    if (!scanResult) return;
    const score = scanResult.score_card?.overall_score || 0;
    const grade = scanResult.score_card?.letter_grade || "N/A";
    const flaws = scanResult.score_card?.confirmed_flaws_count || 0;
    const target = scanResult.raw_target || (scanResult as any).target?.raw_target || targetUrl;
    const text = `EXPOSE Security Audit for ${target}\nScore: ${score}/100 (Grade ${grade})\nConfirmed Flaws: ${flaws}\nScan ID: ${scanResult.id || (scanResult as any).scan_id}\nGenerated via Expose Wire Security Intelligence`;
    navigator.clipboard.writeText(text);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  const handleResetScan = () => {
    setScanResult(null);
    setScanError(null);
    setTargetUrl("");
  };

  // Filtered findings
  const allFindings = scanResult?.findings || [];
  const filteredFindings = allFindings.filter((f) => {
    const matchesSev = filterSeverity === "ALL" || f.severity === filterSeverity;
    const matchesSearch =
      !searchFilter ||
      f.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.description.toLowerCase().includes(searchFilter.toLowerCase()) ||
      (f.rule_id && f.rule_id.toLowerCase().includes(searchFilter.toLowerCase())) ||
      f.category.toLowerCase().includes(searchFilter.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#090b0e] text-slate-900 dark:text-[#e2e8f0] flex flex-col justify-between selection:bg-emerald-500/20 selection:text-emerald-800 dark:selection:text-emerald-300 transition-colors duration-150">
      {/* Top Technical Header */}
      <Header
        health={health}
        readiness={readiness}
        loading={loadingHealth}
        onRefreshHealth={fetchStatus}
        onOpenModal={setActiveModal}
        onResetScan={handleResetScan}
        hasScanResult={!!scanResult}
        onOpenDomainVerify={() => setIsDomainModalOpen(true)}
      />

      {/* Main Analysis Container */}
      <main className="flex-1 w-full max-w-5xl mx-auto px-4 sm:px-6 py-8 sm:py-12 flex flex-col items-center">
        {/* HERO / SCANNER INPUT (Always available or clean toggle) */}
        {!scanResult && (
          <div className="w-full max-w-3xl space-y-6 text-center animate-in fade-in duration-200">
            {/* Direct Technical Tagline */}
            <div className="space-y-2">
              <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100 font-sans">
                See what your website exposes.
              </h1>
              <p className="text-sm text-slate-600 dark:text-slate-400 max-w-xl mx-auto font-sans leading-relaxed">
                Empirical website security intelligence derived purely from raw wire observations, TLS handshakes, DNS records, headers, and asset analysis.
              </p>
            </div>

            {/* Input Card */}
            <form
              onSubmit={handleStartScan}
              className="bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] p-4 sm:p-5 rounded-lg text-left space-y-3 shadow-sm dark:shadow-none"
            >
              <div className="flex flex-col sm:flex-row gap-2.5">
                <div className="relative flex-1">
                  <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 font-mono text-xs select-none">
                    https://
                  </span>
                  <input
                    type="text"
                    placeholder="example.com"
                    value={targetUrl.replace(/^https?:\/\//i, "")}
                    onChange={(e) => {
                      const val = e.target.value.trim();
                      setTargetUrl(val ? (val.startsWith("http") ? val : `https://${val}`) : "");
                    }}
                    disabled={scanning}
                    className="w-full pl-20 pr-4 py-2.5 bg-slate-50 dark:bg-[#090b0e] border border-slate-200 dark:border-[#202735] rounded text-slate-900 dark:text-slate-100 text-xs font-mono focus:outline-none focus:border-slate-400 dark:focus:border-[#3b475d] transition disabled:opacity-50"
                  />
                </div>

                <button
                  type="submit"
                  disabled={!targetUrl || !authorized || scanning}
                  className={`px-5 py-2.5 rounded font-mono text-xs font-semibold flex items-center justify-center gap-2 transition ${
                    targetUrl && authorized && !scanning
                      ? "bg-emerald-500 hover:bg-emerald-400 text-slate-950 cursor-pointer shadow-sm"
                      : "bg-slate-100 dark:bg-[#161d28] text-slate-400 dark:text-slate-500 border border-slate-200 dark:border-[#202735] cursor-not-allowed"
                  }`}
                >
                  {scanning ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Scanning...</span>
                    </>
                  ) : (
                    <>
                      <span>Analyze Website</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </div>

              {/* Sample Target Chips */}
              <div className="flex items-center gap-2 pt-1 text-[11px] font-mono text-slate-500 dark:text-slate-400">
                <span className="text-slate-400 dark:text-slate-500">Presets:</span>
                {["kayoluhayerogroup.net.ng", "example.com", "cloudflare.com"].map((sample) => (
                  <button
                    key={sample}
                    type="button"
                    onClick={() => {
                      setTargetUrl(`https://${sample}`);
                      setAuthorized(true);
                    }}
                    disabled={scanning}
                    className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 dark:bg-[#131923] dark:hover:bg-[#18202d] text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-[#202735] transition"
                  >
                    {sample}
                  </button>
                ))}
              </div>

              {/* Mandatory Consent Checkbox */}
              <div className="pt-3 border-t border-slate-200 dark:border-[#1a222e] flex items-start gap-2.5 text-xs text-slate-600 dark:text-slate-400">
                <input
                  type="checkbox"
                  id="authorization-consent"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  disabled={scanning}
                  className="mt-0.5 rounded bg-white dark:bg-[#090b0e] border-slate-300 dark:border-[#202735] text-emerald-600 focus:ring-0 cursor-pointer"
                />
                <label
                  htmlFor="authorization-consent"
                  className="cursor-pointer select-none leading-relaxed"
                >
                  <strong className="text-slate-800 dark:text-slate-300 font-medium">Mandatory Authorization:</strong> I confirm I have explicit permission to audit this target. All checks are strictly non-destructive and externally observable.
                </label>
              </div>
            </form>

            {/* Scanning Progress Tracker */}
            {scanning && (
              <div className="bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] rounded-lg p-5 text-left space-y-4 animate-in fade-in duration-150 shadow-sm dark:shadow-none">
                <div className="flex items-center justify-between font-mono text-xs">
                  <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-semibold">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>AUDITING WIRE POSTURE...</span>
                  </div>
                  <span className="text-slate-500 dark:text-slate-400">{scanTimer.toFixed(1)}s elapsed</span>
                </div>

                {/* Stepper milestones */}
                <div className="space-y-2 font-mono text-xs">
                  {scanStages.map((stage, idx) => {
                    const isDone = idx < scanStep;
                    const isCurrent = idx === scanStep;
                    return (
                      <div
                        key={idx}
                        className={`flex items-center gap-2.5 transition ${
                          isDone
                            ? "text-emerald-600 dark:text-emerald-400 font-medium"
                            : isCurrent
                            ? "text-slate-900 dark:text-slate-100 font-semibold"
                            : "text-slate-400 dark:text-slate-600"
                        }`}
                      >
                        <span className="w-4 text-center">
                          {isDone ? "✓" : isCurrent ? "→" : "○"}
                        </span>
                        <span>{stage}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Scan Error Alert */}
        {scanError && (
          <div className="w-full max-w-3xl p-4 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-800 dark:text-red-300 text-xs text-left mb-6 flex items-start gap-3 shadow-sm dark:shadow-none">
            <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
            <div className="space-y-1 font-sans flex-1">
              <strong className="block font-mono text-xs text-red-900 dark:text-red-200">
                Audit Blocked or Failed:
              </strong>
              <p className="leading-relaxed">{scanError}</p>
            </div>
          </div>
        )}

        {/* SECURITY AUDIT REPORT (Rendered when scan completes) */}
        {scanResult && scanResult.score_card && (
          <div className="w-full space-y-6 animate-in fade-in duration-200">
            {/* Report Metadata Bar */}
            <div className="bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] rounded-lg p-3 sm:p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-left font-mono text-xs shadow-sm dark:shadow-none">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-bold text-sm text-slate-900 dark:text-slate-100">
                    {scanResult.raw_target || (scanResult as any).target?.raw_target || targetUrl}
                  </span>
                  {scanResult.target?.resolved_ips && scanResult.target.resolved_ips.length > 0 && (
                    <span className="text-[10px] text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-[#131923] border border-slate-200 dark:border-[#202735] px-1.5 py-0.5 rounded font-medium">
                      IP: {scanResult.target.resolved_ips.join(", ")}
                    </span>
                  )}
                  {scanResult.domain_verified ? (
                    <span className="text-[10px] text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-300 dark:border-emerald-800 px-1.5 py-0.5 rounded font-medium flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                      <span>Verified Owner</span>
                    </span>
                  ) : (
                    <button
                      onClick={() => setIsDomainModalOpen(true)}
                      className="text-[10px] text-cyan-600 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-950/30 hover:bg-cyan-100 dark:hover:bg-cyan-900/40 border border-cyan-300 dark:border-cyan-800 px-1.5 py-0.5 rounded font-medium flex items-center gap-1 transition cursor-pointer"
                    >
                      <Shield className="w-3 h-3 text-cyan-500" />
                      <span>Verify Ownership</span>
                    </button>
                  )}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  Audit Timestamp: {scanResult.start_time || new Date().toISOString()}
                </div>
              </div>

              <div className="flex items-center gap-2 flex-wrap shrink-0">
                <button
                  onClick={handleCopySummary}
                  className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-[#131923] dark:hover:bg-[#18202d] text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-[#202735] text-[11px] transition flex items-center gap-1.5"
                  title="Copy technical summary to clipboard"
                >
                  {copiedSummary ? <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedSummary ? "Copied" : "Copy Summary"}</span>
                </button>

                <button
                  onClick={handleExportJson}
                  className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-[#131923] dark:hover:bg-[#18202d] text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-[#202735] text-[11px] transition flex items-center gap-1.5"
                  title="Export raw empirical audit report as JSON"
                >
                  <Download className="w-3 h-3" />
                  <span>Export JSON</span>
                </button>

                <button
                  onClick={handleExportHtml}
                  className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-[#131923] dark:hover:bg-[#18202d] text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-[#202735] text-[11px] transition flex items-center gap-1.5"
                  title="Download standalone self-contained executive HTML report"
                >
                  <FileText className="w-3 h-3" />
                  <span>Export HTML</span>
                </button>

                <button
                  onClick={handleResetScan}
                  className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-white dark:bg-[#18202d] dark:hover:bg-[#202a3b] dark:text-slate-200 border border-slate-900 dark:border-[#2c374b] text-[11px] font-medium transition shadow-xs"
                >
                  New Audit
                </button>
              </div>
            </div>

            {/* Scorecard Hero & 9 Categories */}
            <ScoreCardView
              scoreCard={scanResult.score_card}
              riskAssessment={scanResult.risk_assessment}
              targetUrl={scanResult.raw_target || (scanResult as any).target?.raw_target || targetUrl}
              durationSeconds={scanResult.duration_seconds || 0}
              scanId={scanResult.id || (scanResult as any).scan_id || "N/A"}
              domainVerified={scanResult.domain_verified}
              domainOwnershipProof={scanResult.domain_ownership_proof}
              onOpenVerifyModal={() => setIsDomainModalOpen(true)}
            />

            {/* Primary Report Tabs */}
            <div className="space-y-4 pt-2">
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-[#202735] pb-2">
                <div className="flex gap-2 font-mono text-xs">
                  <button
                    onClick={() => setActiveTab("FINDINGS")}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded transition ${
                      activeTab === "FINDINGS"
                        ? "bg-slate-900 text-white dark:bg-[#18202d] dark:text-white border border-slate-900 dark:border-[#2c374b] font-semibold shadow-xs"
                        : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#0f141c]"
                    }`}
                  >
                    <Shield className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                    <span>Security Findings ({allFindings.length})</span>
                  </button>

                  <button
                    onClick={() => setActiveTab("MATRIX")}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded transition ${
                      activeTab === "MATRIX"
                        ? "bg-slate-900 text-white dark:bg-[#18202d] dark:text-white border border-slate-900 dark:border-[#2c374b] font-semibold shadow-xs"
                        : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#0f141c]"
                    }`}
                  >
                    <TableProperties className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
                    <span>
                      Header Matrix ({scanResult.header_test_matrix?.length || scanResult.score_card?.header_test_matrix?.length || 11} Tests)
                    </span>
                  </button>

                  <button
                    onClick={() => setActiveTab("ATTACK_SURFACE")}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded transition ${
                      activeTab === "ATTACK_SURFACE"
                        ? "bg-slate-900 text-white dark:bg-[#18202d] dark:text-white border border-slate-900 dark:border-[#2c374b] font-semibold shadow-xs"
                        : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#0f141c]"
                    }`}
                  >
                    <Globe className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
                    <span>Attack Surface ({scanResult.attack_surface?.pages?.length || 0} Pages)</span>
                  </button>
                </div>

                <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
                  {activeTab === "FINDINGS"
                    ? "Evidence First. Intelligence Second."
                    : activeTab === "MATRIX"
                    ? "Mozilla HTTP Observatory Test Matrix"
                    : "Public Endpoint & Asset Inventory"}
                </span>
              </div>

              {/* TAB 1: FINDINGS */}
              {activeTab === "FINDINGS" && (
                <div className="space-y-4">
                  {/* Severity Filter & Search Bar */}
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                    {/* Severity Pills */}
                    <div className="flex flex-wrap gap-1 font-mono text-xs">
                      {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => {
                        const count =
                          sev === "ALL"
                            ? allFindings.length
                            : scanResult.severity_counts?.[sev] ||
                              allFindings.filter((f) => f.severity === sev).length;
                        return (
                          <button
                            key={sev}
                            onClick={() => setFilterSeverity(sev)}
                            className={`px-2.5 py-1 rounded transition text-[11px] font-mono ${
                              filterSeverity === sev
                                ? "bg-slate-900 text-white dark:bg-[#1f293a] dark:text-white border border-slate-900 dark:border-[#37455e] font-bold shadow-xs"
                                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735]"
                            }`}
                          >
                            {sev} ({count})
                          </button>
                        );
                      })}
                    </div>

                    {/* Search / Filter Input */}
                    <div className="relative w-full sm:w-60">
                      <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                      <input
                        type="text"
                        placeholder="Search findings or rule IDs..."
                        value={searchFilter}
                        onChange={(e) => setSearchFilter(e.target.value)}
                        className="w-full pl-8 pr-3 py-1 bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] rounded text-slate-900 dark:text-slate-200 text-xs font-mono focus:outline-none focus:border-slate-400 dark:focus:border-[#38465f] transition placeholder:text-slate-400"
                      />
                    </div>
                  </div>

                  {/* Findings Rows List */}
                  <div className="space-y-3">
                    {filteredFindings.length === 0 ? (
                      <div className="p-8 text-center text-slate-500 text-xs font-mono rounded-lg bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] shadow-sm dark:shadow-none">
                        No findings matching current filter criteria.
                      </div>
                    ) : (
                      filteredFindings.map((finding) => (
                        <FindingItem
                          key={finding.id}
                          finding={finding}
                          onVerifyFix={handleVerifyFix}
                          isVerifying={verifyingFindingId === finding.id}
                          verificationFeedback={verificationFeedback[finding.id]}
                        />
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* TAB 2: HTTP HEADER TEST MATRIX */}
              {activeTab === "MATRIX" && (
                <HeaderMatrixView
                  matrix={scanResult.header_test_matrix || scanResult.score_card?.header_test_matrix}
                  targetUrl={scanResult.raw_target || (scanResult as any).target?.raw_target || targetUrl}
                />
              )}

              {/* TAB 3: ATTACK SURFACE */}
              {activeTab === "ATTACK_SURFACE" && (
                <AttackSurfaceView
                  attackSurface={
                    scanResult.attack_surface || {
                      pages: [],
                      apis: [],
                      scripts: [],
                      forms: [],
                      external_dependencies: [],
                    }
                  }
                />
              )}
            </div>
          </div>
        )}
      </main>

      {/* Clean Technical Footer */}
      <footer className="w-full border-t border-slate-200 dark:border-[#1f2838] bg-white dark:bg-[#0d1117] mt-12 py-6 text-xs font-mono text-slate-600 dark:text-slate-400 shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-900 dark:text-slate-200">EXPOSE</span>
            <span className="text-slate-400 dark:text-slate-600">•</span>
            <span>Evidence First. Intelligence Second.</span>
          </div>

          <div className="flex items-center gap-4 text-[11px]">
            <button
              onClick={() => setActiveModal("scope")}
              className="hover:text-slate-900 dark:hover:text-slate-200 transition"
            >
              Scope
            </button>
            <button
              onClick={() => setActiveModal("privacy")}
              className="hover:text-slate-900 dark:hover:text-slate-200 transition"
            >
              Privacy
            </button>
            <button
              onClick={() => setActiveModal("terms")}
              className="hover:text-slate-900 dark:hover:text-slate-200 transition"
            >
              Terms
            </button>
            <button
              onClick={() => setActiveModal("security")}
              className="hover:text-slate-900 dark:hover:text-slate-200 transition"
            >
              Responsible Disclosure
            </button>
          </div>
        </div>
      </footer>

      {/* Trust & Legal Modal */}
      <LegalModal type={activeModal} onClose={() => setActiveModal(null)} />

      {/* Domain Ownership Verification Modal */}
      <DomainVerificationModal
        isOpen={isDomainModalOpen}
        onClose={() => setIsDomainModalOpen(false)}
        defaultDomain={
          scanResult?.target?.host ||
          (targetUrl ? targetUrl.replace(/^https?:\/\//i, "").split("/")[0] : "")
        }
        onVerifiedSuccess={(verifiedDomain, proof) => {
          if (scanResult) {
            setScanResult({
              ...scanResult,
              domain_verified: true,
              domain_ownership_proof: proof,
            });
          }
        }}
      />
    </div>
  );
}

