"use client";

import React, { useState } from "react";
import { AttackSurface } from "./types";
import {
  FileText,
  Code,
  Lock,
  Layers,
  Network,
  Globe,
  Search,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";

interface AttackSurfaceViewProps {
  attackSurface: AttackSurface;
}

export const AttackSurfaceView: React.FC<AttackSurfaceViewProps> = ({
  attackSurface,
}) => {
  const [subTab, setSubTab] = useState<"pages" | "apis" | "forms" | "scripts" | "dependencies">("pages");
  const [query, setQuery] = useState("");

  const pages = attackSurface.pages || [];
  const apis = attackSurface.apis || [];
  const forms = attackSurface.forms || [];
  const scripts = attackSurface.scripts || [];
  const deps = attackSurface.external_dependencies || [];

  const filteredPages = pages.filter(
    (p) => (p.path || p.url).toLowerCase().includes(query.toLowerCase())
  );
  const filteredApis = apis.filter((a) =>
    a.path.toLowerCase().includes(query.toLowerCase())
  );
  const filteredForms = forms.filter((f) =>
    (f.action || "").toLowerCase().includes(query.toLowerCase())
  );
  const filteredScripts = scripts.filter((s) =>
    s.url.toLowerCase().includes(query.toLowerCase())
  );
  const filteredDeps = deps.filter((d) =>
    d.origin.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="space-y-4 text-left">
      {/* Exposure Summary Card */}
      {attackSurface.exposure_summary && (
        <div className="p-4 rounded-lg bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] flex items-start gap-3 text-xs shadow-sm dark:shadow-none">
          <Globe className="w-4 h-4 text-cyan-600 dark:text-cyan-400 shrink-0 mt-0.5" />
          <div className="space-y-1 font-sans">
            <strong className="text-slate-900 dark:text-slate-200 block font-mono text-xs">
              Public Attack Surface Statement:
            </strong>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
              {attackSurface.exposure_summary}
            </p>
          </div>
        </div>
      )}

      {/* Subnavigation Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-[#202735] pb-3">
        <div className="flex flex-wrap gap-1.5 font-mono text-xs">
          <button
            onClick={() => setSubTab("pages")}
            className={`px-3 py-1.5 rounded transition ${
              subTab === "pages"
                ? "bg-slate-900 text-white dark:bg-[#18202d] dark:text-white border border-slate-900 dark:border-[#2b374d] font-semibold shadow-xs"
                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#0f141c]"
            }`}
          >
            Pages ({pages.length})
          </button>
          <button
            onClick={() => setSubTab("apis")}
            className={`px-3 py-1.5 rounded transition ${
              subTab === "apis"
                ? "bg-slate-900 text-white dark:bg-[#18202d] dark:text-white border border-slate-900 dark:border-[#2b374d] font-semibold shadow-xs"
                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#0f141c]"
            }`}
          >
            APIs ({apis.length})
          </button>
          <button
            onClick={() => setSubTab("forms")}
            className={`px-3 py-1.5 rounded transition ${
              subTab === "forms"
                ? "bg-slate-900 text-white dark:bg-[#18202d] dark:text-white border border-slate-900 dark:border-[#2b374d] font-semibold shadow-xs"
                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#0f141c]"
            }`}
          >
            Forms ({forms.length})
          </button>
          <button
            onClick={() => setSubTab("scripts")}
            className={`px-3 py-1.5 rounded transition ${
              subTab === "scripts"
                ? "bg-slate-900 text-white dark:bg-[#18202d] dark:text-white border border-slate-900 dark:border-[#2b374d] font-semibold shadow-xs"
                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#0f141c]"
            }`}
          >
            Scripts & SRI ({scripts.length})
          </button>
          <button
            onClick={() => setSubTab("dependencies")}
            className={`px-3 py-1.5 rounded transition ${
              subTab === "dependencies"
                ? "bg-slate-900 text-white dark:bg-[#18202d] dark:text-white border border-slate-900 dark:border-[#2b374d] font-semibold shadow-xs"
                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#0f141c]"
            }`}
          >
            3rd-Party Origins ({deps.length})
          </button>
        </div>

        {/* Quick Filter Box */}
        <div className="relative w-full sm:w-56">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Filter items..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1 bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] rounded text-slate-900 dark:text-slate-200 text-xs font-mono focus:outline-none focus:border-slate-400 dark:focus:border-[#38465f] transition placeholder:text-slate-400"
          />
        </div>
      </div>

      {/* Tab Panels */}
      <div className="bg-white dark:bg-[#0d1117] border border-slate-200 dark:border-[#202735] rounded-lg overflow-hidden shadow-sm dark:shadow-none">
        {/* PAGES TABLE */}
        {subTab === "pages" && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-50 dark:bg-[#111721] border-b border-slate-200 dark:border-[#202735] text-slate-600 dark:text-slate-400 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">Discovered Path / URL</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Discovery Source</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-[#171e29]">
                {filteredPages.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="p-6 text-center text-slate-500 font-sans">
                      No discovered pages matching query.
                    </td>
                  </tr>
                ) : (
                  filteredPages.map((page, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-[#111720] transition">
                      <td className="py-2 px-4 text-slate-800 dark:text-slate-200 truncate max-w-md font-medium" title={page.url}>
                        {page.path || page.url}
                      </td>
                      <td className="py-2 px-4">
                        {page.status_code ? (
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              page.status_code < 400
                                ? "bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800/40"
                                : "bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-400 border border-red-300 dark:border-red-800/40"
                            }`}
                          >
                            HTTP {page.status_code}
                          </span>
                        ) : (
                          <span className="text-slate-500 text-[10px]">PASSIVE</span>
                        )}
                      </td>
                      <td className="py-2 px-4 text-slate-500 dark:text-slate-400 text-[11px]">
                        {page.discovered_via}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* APIS TABLE */}
        {subTab === "apis" && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-50 dark:bg-[#111721] border-b border-slate-200 dark:border-[#202735] text-slate-600 dark:text-slate-400 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">Method</th>
                  <th className="py-2.5 px-4">Referenced API Route</th>
                  <th className="py-2.5 px-4">Visibility</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-[#171e29]">
                {filteredApis.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="p-6 text-center text-slate-500 font-sans">
                      No public API endpoints detected in client-side scripts.
                    </td>
                  </tr>
                ) : (
                  filteredApis.map((api, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-[#111720] transition">
                      <td className="py-2 px-4">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-50 dark:bg-cyan-950/60 text-cyan-800 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-800/40 font-bold">
                          {api.method}
                        </span>
                      </td>
                      <td className="py-2 px-4 text-slate-800 dark:text-slate-200 break-all font-medium">
                        {api.path}
                      </td>
                      <td className="py-2 px-4 text-slate-500 dark:text-slate-400 text-[11px]">
                        Client-side referenced
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* FORMS TABLE */}
        {subTab === "forms" && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-50 dark:bg-[#111721] border-b border-slate-200 dark:border-[#202735] text-slate-600 dark:text-slate-400 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">Action URL & Method</th>
                  <th className="py-2.5 px-4">Transport Security</th>
                  <th className="py-2.5 px-4">Input Fields & Sensitive Data</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-[#171e29]">
                {filteredForms.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="p-6 text-center text-slate-500 font-sans">
                      No HTML submission forms detected on target.
                    </td>
                  </tr>
                ) : (
                  filteredForms.map((form, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-[#111720] transition">
                      <td className="py-2.5 px-4">
                        <div className="font-semibold text-slate-800 dark:text-slate-200">
                          <span className="text-cyan-600 dark:text-cyan-400 mr-2">{form.method}</span>
                          <span className="truncate max-w-sm inline-block align-bottom">{form.action}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-4">
                        {form.is_secure_action ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800/40 font-bold">
                            ✓ HTTPS SECURE
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-400 border border-red-300 dark:border-red-800/40 font-bold">
                            ⚠️ INSECURE ACTION
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4">
                        <div className="flex flex-wrap gap-1">
                          {form.inputs.map((inp, iIdx) => (
                            <span
                              key={iIdx}
                              className={`px-1.5 py-0.5 rounded text-[10px] border ${
                                inp.is_sensitive
                                  ? "bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-700/50 font-bold"
                                  : "bg-slate-100 dark:bg-[#131923] text-slate-600 dark:text-slate-400 border-slate-200 dark:border-[#202735]"
                              }`}
                            >
                              {inp.name} ({inp.input_type})
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* SCRIPTS TABLE */}
        {subTab === "scripts" && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-50 dark:bg-[#111721] border-b border-slate-200 dark:border-[#202735] text-slate-600 dark:text-slate-400 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">Script Bundle</th>
                  <th className="py-2.5 px-4">CDN Provider</th>
                  <th className="py-2.5 px-4">Subresource Integrity (SRI)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-[#171e29]">
                {filteredScripts.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="p-6 text-center text-slate-500 font-sans">
                      No external scripts identified.
                    </td>
                  </tr>
                ) : (
                  filteredScripts.map((script, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-[#111720] transition">
                      <td className="py-2 px-4 text-slate-800 dark:text-slate-200 truncate max-w-md font-medium" title={script.url}>
                        {script.url}
                      </td>
                      <td className="py-2 px-4 text-slate-500 dark:text-slate-400 text-[11px]">
                        {script.cdn_provider || "Self-Hosted / Direct"}
                      </td>
                      <td className="py-2 px-4">
                        {script.has_sri ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800/40 font-bold">
                            ✓ SRI PRESENT
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 border border-slate-300 dark:border-slate-700">
                            NO SRI HASH
                          </span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* DEPENDENCIES TABLE */}
        {subTab === "dependencies" && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-50 dark:bg-[#111721] border-b border-slate-200 dark:border-[#202735] text-slate-600 dark:text-slate-400 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">Third-Party Origin</th>
                  <th className="py-2.5 px-4">Resource Category</th>
                  <th className="py-2.5 px-4">Resource Count</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-[#171e29]">
                {filteredDeps.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="p-6 text-center text-slate-500 font-sans">
                      Target operates self-contained without external third-party origins.
                    </td>
                  </tr>
                ) : (
                  filteredDeps.map((dep, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-[#111720] transition">
                      <td className="py-2 px-4 text-slate-800 dark:text-slate-200 font-semibold">
                        {dep.origin}
                      </td>
                      <td className="py-2 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/40 font-mono font-medium">
                          {dep.category}
                        </span>
                      </td>
                      <td className="py-2 px-4 text-slate-500 dark:text-slate-400">
                        {dep.resource_count} resource(s) loaded
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
