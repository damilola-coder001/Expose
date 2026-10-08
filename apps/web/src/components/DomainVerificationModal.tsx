"use client";

import React, { useState, useEffect } from "react";
import {
  X,
  ShieldCheck,
  CheckCircle2,
  Copy,
  Check,
  Globe,
  RefreshCw,
  AlertCircle,
  FileCode,
  Network,
} from "lucide-react";
import { DomainChallenge } from "./types";

interface DomainVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
  defaultDomain?: string;
  onVerifiedSuccess?: (domain: string, proof: string) => void;
}

export const DomainVerificationModal: React.FC<DomainVerificationModalProps> = ({
  isOpen,
  onClose,
  defaultDomain = "",
  onVerifiedSuccess,
}) => {
  const [domain, setDomain] = useState(defaultDomain);
  const [method, setMethod] = useState<"dns" | "http">("dns");
  const [challenge, setChallenge] = useState<DomainChallenge | null>(null);
  const [loadingChallenge, setLoadingChallenge] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyStatus, setVerifyStatus] = useState<{
    success: boolean;
    message: string;
    proof?: string;
  } | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (defaultDomain) {
      setDomain(defaultDomain);
    }
  }, [defaultDomain]);

  useEffect(() => {
    if (isOpen && domain) {
      fetchChallenge(domain);
    }
  }, [isOpen, domain]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const fetchChallenge = async (targetDomain: string) => {
    if (!targetDomain.trim()) return;
    setLoadingChallenge(true);
    setVerifyStatus(null);
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
    try {
      const res = await fetch(`${apiUrl}/api/v1/domains/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: targetDomain.trim() }),
      });
      if (res.ok) {
        const data = await res.json();
        setChallenge(data);
      }
    } catch {
      // Offline fallback token generation simulation
      const fallbackToken = `expose-verification=manual-token-${targetDomain.replace(/[^a-z0-9]/gi, "")}`;
      setChallenge({
        domain: targetDomain,
        token: fallbackToken,
        dns_record_name: `_expose-challenge.${targetDomain}`,
        dns_record_type: "TXT",
        dns_record_value: fallbackToken,
        http_url: `https://${targetDomain}/.well-known/expose-challenge.txt`,
        http_expected_content: fallbackToken,
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 7 * 86400000).toISOString(),
        instructions: {
          dns_txt: `Create a DNS TXT record for host '_expose-challenge.${targetDomain}' with value '${fallbackToken}'.`,
          http_well_known: `Upload a text file to 'https://${targetDomain}/.well-known/expose-challenge.txt' containing '${fallbackToken}'.`,
        },
      });
    } finally {
      setLoadingChallenge(false);
    }
  };

  const handleVerify = async () => {
    if (!domain.trim()) return;
    setVerifying(true);
    setVerifyStatus(null);
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
    const methodParam = method === "dns" ? "dns_txt" : "http_well_known";

    try {
      const res = await fetch(`${apiUrl}/api/v1/domains/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: domain.trim(),
          method: methodParam,
        }),
      });

      const data = await res.json();
      if (res.ok && data.verified) {
        setVerifyStatus({
          success: true,
          message: data.message || "Ownership verified successfully!",
          proof: data.record?.proof || data.message,
        });
        if (onVerifiedSuccess) {
          onVerifiedSuccess(domain.trim(), data.message);
        }
      } else {
        setVerifyStatus({
          success: false,
          message:
            data.message ||
            "Verification record not detected yet. If you just added the DNS record, please allow 1-2 minutes for global DNS propagation.",
        });
      }
    } catch (err: any) {
      setVerifyStatus({
        success: false,
        message: err.message || "Failed to contact verification service.",
      });
    } finally {
      setVerifying(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden text-slate-100 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight">Verify Domain Ownership</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Prove asset control to enable verified badges & enterprise scan access
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Domain Input */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Target Domain
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>
              <button
                type="button"
                onClick={() => fetchChallenge(domain)}
                disabled={loadingChallenge || !domain.trim()}
                className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-xl transition flex items-center gap-2 border border-slate-700 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${loadingChallenge ? "animate-spin" : ""}`} />
                <span>Get Token</span>
              </button>
            </div>
          </div>

          {/* Verification Method Toggle */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Verification Method
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setMethod("dns")}
                className={`flex items-center gap-3 p-3.5 rounded-xl border text-left transition ${
                  method === "dns"
                    ? "bg-cyan-500/10 border-cyan-500/40 text-cyan-300"
                    : "bg-slate-950/50 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <Network className="w-5 h-5 flex-shrink-0" />
                <div>
                  <div className="text-sm font-semibold text-slate-200">DNS TXT Record</div>
                  <div className="text-xs text-slate-500">Recommended for domains & apexes</div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setMethod("http")}
                className={`flex items-center gap-3 p-3.5 rounded-xl border text-left transition ${
                  method === "http"
                    ? "bg-cyan-500/10 border-cyan-500/40 text-cyan-300"
                    : "bg-slate-950/50 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <FileCode className="w-5 h-5 flex-shrink-0" />
                <div>
                  <div className="text-sm font-semibold text-slate-200">HTTP .well-known</div>
                  <div className="text-xs text-slate-500">Quick upload to web server root</div>
                </div>
              </button>
            </div>
          </div>

          {/* Setup Instructions */}
          {challenge && (
            <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-5 space-y-4">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                <span>Setup Instructions</span>
                <span className="text-[10px] text-slate-500">Valid for 7 days</span>
              </div>

              {method === "dns" ? (
                <div className="space-y-3">
                  <div>
                    <div className="text-xs text-slate-400 mb-1">Host / Record Name:</div>
                    <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 font-mono text-xs text-cyan-300">
                      <span className="truncate">{challenge.dns_record_name}</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.dns_record_name, "dns_name")}
                        className="ml-2 text-slate-400 hover:text-white"
                      >
                        {copiedKey === "dns_name" ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-slate-400 mb-1">Record Type:</div>
                    <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 font-mono text-xs text-slate-300">
                      TXT
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-slate-400 mb-1">Record Value / Token:</div>
                    <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 font-mono text-xs text-cyan-300">
                      <span className="truncate">{challenge.token}</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.token, "dns_val")}
                        className="ml-2 text-slate-400 hover:text-white"
                      >
                        {copiedKey === "dns_val" ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <div>
                    <div className="text-xs text-slate-400 mb-1">Create File At:</div>
                    <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 font-mono text-xs text-cyan-300">
                      <span className="truncate">{challenge.http_url}</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.http_url, "http_url")}
                        className="ml-2 text-slate-400 hover:text-white"
                      >
                        {copiedKey === "http_url" ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-slate-400 mb-1">File Contents:</div>
                    <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 font-mono text-xs text-cyan-300">
                      <span className="truncate">{challenge.token}</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.token, "http_val")}
                        className="ml-2 text-slate-400 hover:text-white"
                      >
                        {copiedKey === "http_val" ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Verification Status Feedback */}
          {verifyStatus && (
            <div
              className={`p-4 rounded-xl border flex items-start gap-3 animate-in fade-in duration-200 ${
                verifyStatus.success
                  ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                  : "bg-amber-500/10 border-amber-500/30 text-amber-300"
              }`}
            >
              {verifyStatus.success ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
              )}
              <div className="text-xs leading-relaxed">
                <div className="font-semibold text-sm mb-0.5">
                  {verifyStatus.success ? "Domain Verified!" : "Verification Incomplete"}
                </div>
                <div>{verifyStatus.message}</div>
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-6 border-t border-slate-800 bg-slate-900/50 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2.5 rounded-xl border border-slate-800 text-slate-300 hover:bg-slate-800 text-sm font-medium transition"
          >
            Close
          </button>
          <button
            type="button"
            onClick={handleVerify}
            disabled={verifying || !domain.trim()}
            className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-sm font-bold shadow-lg shadow-cyan-500/20 transition flex items-center gap-2 disabled:opacity-50"
          >
            {verifying ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Checking Wire Proof...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>Verify Ownership Now</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
