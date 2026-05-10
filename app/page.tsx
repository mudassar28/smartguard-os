"use client";
import { useState, useEffect, useRef } from "react";
import { analyzeContract } from "./actions";

// ─── Types ───────────────────────────────────────────────────────────────────
interface AuditResult {
  riskScore: number;
  counts: { critical: number; high: number; medium: number; low: number };
  executive: string;
  vulnerabilities: string;
  redTeam: string;
  remediation: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Robust JSON extractor — 4 strategies, no custom brace-walking
 * (custom walkers break on escaped quotes inside JSON string values)
 *
 * 1. Strip \x60\x60\x60json / \x60\x60\x60 fences → JSON.parse
 * 2. JSON.parse(raw.trim()) — handles clean response
 * 3. JSON.parse from first { to last } — handles surrounding whitespace/text
 * 4. JSON.parse from first { to end of string — handles trailing garbage
 */
const parseAuditJSON = (raw: string): AuditResult | null => {
  const validate = (parsed: any): AuditResult | null => {
    if (
      parsed &&
      typeof parsed === "object" &&
      typeof parsed.riskScore === "number" &&
      parsed.counts &&
      typeof parsed.executive === "string"
    ) {
      return {
        riskScore: Math.max(0, Math.min(100, parsed.riskScore)),
        counts: {
          critical: Number(parsed.counts?.critical) || 0,
          high: Number(parsed.counts?.high) || 0,
          medium: Number(parsed.counts?.medium) || 0,
          low: Number(parsed.counts?.low) || 0,
        },
        executive: parsed.executive || "",
        vulnerabilities: parsed.vulnerabilities || "No vulnerability data returned.",
        redTeam: parsed.redTeam || "No red team simulation data returned.",
        remediation: parsed.remediation || "No remediation data returned.",
      };
    }
    return null;
  };

  const tryParse = (s: string): AuditResult | null => {
    try { return validate(JSON.parse(s)); } catch { return null; }
  };

  // Strategy 1: strip markdown code fences
  const fence = raw.match(/\x60\x60\x60(?:json)?\s*([\s\S]*?)\x60\x60\x60/);
  if (fence) { const r = tryParse(fence[1].trim()); if (r) return r; }

  // Strategy 2: direct parse of trimmed string (Gemini returned clean JSON)
  const r2 = tryParse(raw.trim());
  if (r2) return r2;

  // Strategy 3: slice from first { to last } (handles preamble/postamble text)
  const first = raw.indexOf("{");
  const last = raw.lastIndexOf("}");
  if (first !== -1 && last !== -1 && last > first) {
    const r3 = tryParse(raw.slice(first, last + 1));
    if (r3) return r3;
  }

  // Strategy 4: slice from first { to end (handles trailing non-JSON text)
  if (first !== -1) {
    const r4 = tryParse(raw.slice(first));
    if (r4) return r4;
  }

  return null;
};

const getRiskColor = (score: number) => {
  if (score >= 75) return { text: "text-rose-400", stroke: "#f43f5e", label: "CRITICAL RISK" };
  if (score >= 50) return { text: "text-orange-400", stroke: "#fb923c", label: "HIGH RISK" };
  if (score >= 25) return { text: "text-yellow-400", stroke: "#facc15", label: "MEDIUM RISK" };
  return { text: "text-emerald-400", stroke: "#34d399", label: "LOW RISK" };
};

// ─── SVG Gauge Component ──────────────────────────────────────────────────────
const RiskGauge = ({ score }: { score: number }) => {
  const { text, stroke, label } = getRiskColor(score);
  const radius = 54;
  const circumference = Math.PI * radius; // half circle
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="140" height="80" viewBox="0 0 140 80">
        {/* Track */}
        <path
          d="M 14 74 A 56 56 0 0 1 126 74"
          fill="none"
          stroke="#1e293b"
          strokeWidth="10"
          strokeLinecap="round"
        />
        {/* Progress */}
        <path
          d="M 14 74 A 56 56 0 0 1 126 74"
          fill="none"
          stroke={stroke}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1s ease, stroke 0.5s ease" }}
        />
        {/* Score text */}
        <text x="70" y="68" textAnchor="middle" fontSize="24" fontWeight="bold" fill="white" fontFamily="monospace">
          {score}
        </text>
      </svg>
      <span className={`text-xs font-mono font-bold tracking-widest ${text}`}>{label}</span>
    </div>
  );
};

// ─── Line-numbered Code Editor ────────────────────────────────────────────────
const CodeEditor = ({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) => {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const lineNumRef = useRef<HTMLDivElement>(null);
  const lines = value.split("\n");

  const syncScroll = () => {
    if (textareaRef.current && lineNumRef.current) {
      lineNumRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

  return (
    <div
      className="relative flex rounded-xl overflow-hidden border border-slate-700/60 bg-[#090f1a]"
      style={{ height: "480px", fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}
    >
      {/* Line numbers */}
      <div
        ref={lineNumRef}
        className="select-none overflow-hidden text-right pr-3 pl-3 pt-4 text-slate-600 text-xs leading-[1.6rem] bg-[#0b1220] border-r border-slate-800/60 shrink-0"
        style={{ minWidth: "48px" }}
        aria-hidden
      >
        {lines.map((_, i) => (
          <div key={i}>{i + 1}</div>
        ))}
      </div>
      {/* Textarea */}
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onScroll={syncScroll}
        spellCheck={false}
        placeholder="// Paste your Solidity smart contract here..."
        className="flex-1 resize-none bg-transparent text-emerald-300 text-xs leading-[1.6rem] pt-4 px-4 pb-4 focus:outline-none placeholder-slate-700 overflow-auto"
        style={{ fontFamily: "inherit" }}
      />
    </div>
  );
};

// ─── Tab Button ───────────────────────────────────────────────────────────────
const TabBtn = ({
  active,
  onClick,
  icon,
  label,
  badge,
}: {
  active: boolean;
  onClick: () => void;
  icon: string;
  label: string;
  badge?: number;
}) => (
  <button
    onClick={onClick}
    className={`flex items-center gap-1.5 px-3 py-2 text-xs font-mono font-semibold rounded-lg transition-all whitespace-nowrap ${
      active
        ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/40"
        : "text-slate-500 hover:text-slate-300 border border-transparent"
    }`}
  >
    <span>{icon}</span>
    <span className="hidden sm:inline">{label}</span>
    {badge !== undefined && badge > 0 && (
      <span className="bg-rose-500/80 text-white text-[10px] px-1.5 rounded-full">{badge}</span>
    )}
  </button>
);

// ─── Markdown renderer with proper code-block support ────────────────────────
const MarkdownBlock = ({ content }: { content: string }) => {
  // Split into segments: either a fenced code block or regular lines
 type PageSegment = { type: "code"; lang?: string | null; body: string } | { type: "lines"; body: string | string[] };
const segments: PageSegment[] = [];
  const lines = content.split("\n");
  let i = 0;
  while (i < lines.length) {
    const fenceMatch = lines[i].match(/^\x60\x60\x60(\w*)/);
    if (fenceMatch) {
      const lang = fenceMatch[1];
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("\x60\x60\x60")) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing fence
      segments.push({ type: "code", lang, body: codeLines.join("\n") });
    } else {
      const textLines: string[] = [];
      while (i < lines.length && !lines[i].match(/^\x60\x60\x60/)) {
        textLines.push(lines[i]);
        i++;
      }
      segments.push({ type: "lines", body: textLines });
    }
  }

  return (
    <div className="space-y-2 text-sm leading-relaxed font-mono">
      {segments.map((seg, si) => {
        if (seg.type === "code") {
          return (
            <div key={si} className="rounded-lg overflow-hidden border border-slate-700/50 my-3">
              {seg.lang && (
                <div className="bg-slate-800/80 px-3 py-1 text-[10px] text-cyan-400/70 border-b border-slate-700/50 uppercase tracking-widest">
                  {seg.lang}
                </div>
              )}
              <pre className="bg-[#060c18] p-4 overflow-x-auto text-xs text-emerald-300 leading-relaxed whitespace-pre">
                {seg.body}
              </pre>
            </div>
          );
        }
        return (
          <div key={si} className="space-y-1">
            {(seg as { type: "lines"; body: string[] }).body.map((line, li) => {
              if (line.startsWith("### "))
                return <p key={li} className="text-cyan-300 font-bold mt-3 text-base">{line.slice(4)}</p>;
              if (line.startsWith("## "))
                return <p key={li} className="text-cyan-200 font-bold mt-4 text-lg border-b border-slate-700 pb-1">{line.slice(3)}</p>;
              if (line.startsWith("# "))
                return <p key={li} className="text-white font-extrabold mt-4 text-xl">{line.slice(2)}</p>;
              if (line.startsWith("**") && line.endsWith("**"))
                return <p key={li} className="text-slate-100 font-bold mt-2">{line.slice(2, -2)}</p>;
              if (line.startsWith("🔴") || line.startsWith("🚨"))
                return <p key={li} className="text-rose-400 font-semibold">{line}</p>;
              if (line.startsWith("🟠"))
                return <p key={li} className="text-orange-400 font-semibold">{line}</p>;
              if (line.startsWith("🟡") || line.startsWith("⚠️"))
                return <p key={li} className="text-yellow-400 font-semibold">{line}</p>;
              if (line.startsWith("🟢") || line.startsWith("✅"))
                return <p key={li} className="text-emerald-400 font-semibold">{line}</p>;
              if (line.match(/^\d+\. /))
                return <p key={li} className="text-slate-200 pl-2 font-semibold mt-2">{line}</p>;
              if (line.startsWith("- ") || line.startsWith("* "))
                return (
                  <p key={li} className="text-slate-300 pl-4 flex gap-2">
                    <span className="text-cyan-500 shrink-0">›</span>
                    <span>{line.slice(2)}</span>
                  </p>
                );
              if (!line.trim()) return <div key={li} className="h-1.5" />;
              return <p key={li} className="text-slate-300">{line}</p>;
            })}
          </div>
        );
      })}
    </div>
  );
};

// ─── PDF Export ───────────────────────────────────────────────────────────────
const exportPDF = (audit: AuditResult, contractCode: string) => {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>SmartGuard Audit Report</title>
  <style>
    body { font-family: 'Courier New', monospace; background: #fff; color: #111; padding: 40px; }
    h1 { color: #0891b2; border-bottom: 2px solid #0891b2; padding-bottom: 8px; }
    h2 { color: #0e7490; margin-top: 28px; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: bold; margin: 2px; }
    .critical { background: #fef2f2; color: #b91c1c; }
    .high { background: #fff7ed; color: #c2410c; }
    .medium { background: #fefce8; color: #a16207; }
    .low { background: #f0fdf4; color: #15803d; }
    .score { font-size: 48px; font-weight: bold; }
    pre { background: #f8fafc; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 12px; }
    .section { margin-top: 24px; padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; }
    @media print { body { padding: 20px; } }
  </style>
</head>
<body>
  <h1>🛡️ SmartGuard_OS — Security Audit Report</h1>
  <p><b>Generated:</b> ${new Date().toLocaleString()}</p>

  <h2>Risk Score</h2>
  <div class="score" style="color:${audit.riskScore >= 75 ? '#e11d48' : audit.riskScore >= 50 ? '#ea580c' : audit.riskScore >= 25 ? '#ca8a04' : '#16a34a'}">${audit.riskScore}/100</div>
  <div>
    <span class="badge critical">🔴 Critical: ${audit.counts.critical}</span>
    <span class="badge high">🟠 High: ${audit.counts.high}</span>
    <span class="badge medium">🟡 Medium: ${audit.counts.medium}</span>
    <span class="badge low">🟢 Low: ${audit.counts.low}</span>
  </div>

  <div class="section"><h2>Executive Summary</h2><pre>${audit.executive}</pre></div>
  <div class="section"><h2>Vulnerability Details</h2><pre>${audit.vulnerabilities}</pre></div>
  <div class="section"><h2>Red Team Simulation</h2><pre>${audit.redTeam}</pre></div>
  <div class="section"><h2>Remediation</h2><pre>${audit.remediation}</pre></div>
  <div class="section"><h2>Audited Contract Source</h2><pre>${contractCode.replace(/</g, "&lt;")}</pre></div>
</body>
</html>`;

  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, "_blank");
  if (win) {
    win.onload = () => {
      win.focus();
      win.print();
    };
  }
};

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function Home() {
  const [contractCode, setContractCode] = useState("");
  const [audit, setAudit] = useState<AuditResult | null>(null);
  const [rawOutput, setRawOutput] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<"executive" | "vulns" | "redteam" | "remediation">("executive");
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState("");
  const progressRef = useRef<ReturnType<typeof setInterval> | null>(null);

  
  const startProgress = () => {
    setProgress(0);
    const messages = [
      "Initializing triage protocol...",
      "Scanning for reentrancy vectors...",
      "Checking access control logic...",
      "Analyzing arithmetic operations...",
      "Running gas optimization checks...",
      "Generating threat intelligence...",
      "Compiling audit report...",
    ];
    let step = 0;
    progressRef.current = setInterval(() => {
      setProgress((p) => {
        if (p >= 92) return p;
        return p + Math.random() * 5;
      });
      setStatusMsg(messages[step % messages.length]);
      step++;
    }, 800);
  };

  const stopProgress = () => {
    if (progressRef.current) clearInterval(progressRef.current);
    setProgress(100);
    setTimeout(() => setProgress(0), 1200);
  };

  const handleAnalyze = async () => {
    if (!contractCode.trim()) return;
    setIsAnalyzing(true);
    setAudit(null);
    setRawOutput("");
    startProgress();

    try {
      const rawResponse = await analyzeContract(contractCode);
      setRawOutput(rawResponse);

      const parsed = parseAuditJSON(rawResponse);
      if (parsed) {
        setAudit(parsed);
        setActiveTab("executive");
      } else {
        // True fallback: model returned prose/refused (e.g. invalid input like "hello")
        // Show a clear error in the raw output panel — do NOT fake a 50/100 score
        setRawOutput(
          "⚠️  The model did not return structured JSON.\n\n" +
          "This usually means the input is not a valid Solidity contract.\n" +
          "Please paste a real .sol contract and try again.\n\n" +
          "─── Raw model response ───\n\n" + rawResponse
        );
        // Leave audit as null so the UI shows the clean "awaiting payload" state
      }
    } catch (error: any) {
      setRawOutput(`❌ API CONNECTION FAILED: ${error.message}`);
    }
    stopProgress();
    setIsAnalyzing(false);
  };

  const { text: riskText, label: riskLabel } = audit
    ? getRiskColor(audit.riskScore)
    : { text: "text-slate-500", label: "" };

  return (
    <div
      className="min-h-screen text-slate-300 p-3 md:p-6 selection:bg-cyan-900 selection:text-cyan-100"
      style={{
        background: "radial-gradient(ellipse at 20% 10%, #0c1628 0%, #060b14 60%, #070d1a 100%)",
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      }}
    >
      {/* Scanline overlay */}
      <div
        className="fixed inset-0 pointer-events-none z-0 opacity-[0.025]"
        style={{
          backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.3) 2px, rgba(0,0,0,0.3) 4px)",
        }}
      />

      <div className="relative z-10 max-w-7xl mx-auto space-y-5">

        {/* ── Header ── */}
        <header className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-5 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div
              className="w-11 h-11 rounded-xl flex items-center justify-center text-2xl border border-cyan-500/30"
              style={{ background: "linear-gradient(135deg, #0c2037 0%, #0a1628 100%)", boxShadow: "0 0 20px rgba(6,182,212,0.15)" }}
            >
              🛡️
            </div>
            <div>
              <h1 className="text-2xl font-extrabold text-white tracking-wider">
                SmartGuard<span className="text-cyan-400">_OS</span>
                <span className="ml-2 text-[10px] font-normal text-slate-600 border border-slate-700 px-2 py-0.5 rounded-full">v2.0</span>
              </h1>
              <p className="text-[10px] text-slate-600 uppercase tracking-[0.2em]">Web3 Triage & Threat Intelligence Platform</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-emerald-950/20 border border-emerald-900/40 px-3 py-2 rounded-lg">
  <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
  <span className="text-[10px] text-emerald-400 uppercase tracking-widest">API Secured</span>
    </div>
            {audit && (
              <button
                onClick={() => exportPDF(audit, contractCode)}
                className="flex items-center gap-2 px-3 py-2 text-xs bg-violet-600/20 border border-violet-500/40 hover:bg-violet-600/30 text-violet-300 rounded-lg transition-all"
              >
                <span>📄</span>
                <span className="hidden sm:inline">Export PDF</span>
              </button>
            )}
          </div>
        </header>

        {/* ── Progress Bar ── */}
        {isAnalyzing && (
          <div className="space-y-1.5">
            <div className="flex justify-between text-[10px] text-slate-500">
              <span className="animate-pulse">{statusMsg}</span>
              <span>{Math.round(progress)}%</span>
            </div>
            <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 rounded-full transition-all duration-700"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* ── Security Posture Strip ── */}
        {audit && (
          <div
            className="rounded-2xl border border-slate-700/50 p-5 grid grid-cols-2 sm:grid-cols-5 gap-4 items-center"
            style={{ background: "linear-gradient(135deg, #0b1628 0%, #0a1220 100%)" }}
          >
            {/* Gauge */}
            <div className="col-span-2 sm:col-span-1 flex justify-center">
              <RiskGauge score={audit.riskScore} />
            </div>

            {/* Divider */}
            <div className="hidden sm:block w-px bg-slate-800 self-stretch mx-2" />

            {/* Counts */}
            {[
              { label: "Critical", count: audit.counts.critical, color: "rose", icon: "🔴" },
              { label: "High", count: audit.counts.high, color: "orange", icon: "🟠" },
              { label: "Medium", count: audit.counts.medium, color: "yellow", icon: "🟡" },
              { label: "Low", count: audit.counts.low, color: "emerald", icon: "🟢" },
            ].map(({ label, count, color, icon }) => (
              <div
                key={label}
                className={`flex flex-col items-center gap-1 p-3 rounded-xl bg-${color}-950/20 border border-${color}-900/30`}
              >
                <span className="text-lg">{icon}</span>
                <span className={`text-3xl font-extrabold text-${color}-400`}>{count}</span>
                <span className={`text-[10px] text-${color}-600 uppercase tracking-widest`}>{label}</span>
              </div>
            ))}
          </div>
        )}

        {/* ── Main Grid ── */}
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_1.1fr] gap-5">

          {/* Left: Code Editor */}
          <div className="space-y-3">
            {/* IDE Title Bar */}
            <div className="flex items-center justify-between bg-[#0b1220] border border-slate-800/60 rounded-t-xl px-4 py-2.5">
              <div className="flex items-center gap-1.5">
                <div className="w-3 h-3 rounded-full bg-rose-500/70" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
                <div className="w-3 h-3 rounded-full bg-emerald-500/70" />
              </div>
              <span className="text-xs text-slate-500">contract.sol</span>
              <button
                onClick={() => setContractCode("")}
                className="text-[10px] text-slate-600 hover:text-rose-400 transition-colors"
              >
                ✕ clear
              </button>
            </div>

            <div className="-mt-3">
              <CodeEditor value={contractCode} onChange={setContractCode} />
            </div>

            {/* Analyze Button */}
            <button
              onClick={handleAnalyze}
              disabled={isAnalyzing || !contractCode.trim()}
              className="w-full py-3.5 rounded-xl font-bold text-sm text-white tracking-widest uppercase transition-all disabled:opacity-40 disabled:cursor-not-allowed relative overflow-hidden"
              style={{
                background: isAnalyzing
                  ? "linear-gradient(135deg, #164e63, #155e75)"
                  : "linear-gradient(135deg, #0e7490, #0891b2)",
                boxShadow: isAnalyzing ? "none" : "0 0 30px -5px rgba(6,182,212,0.5)",
              }}
            >
              <span className="relative z-10 flex items-center justify-center gap-2">
                {isAnalyzing ? (
                  <>
                    <svg className="animate-spin h-4 w-4" xmlns="[http://www.w3.org/2000/svg](http://www.w3.org/2000/svg)" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Executing Triage Protocol...
                  </>
                ) : (
                  <>⚡ Initiate Security Scan</>
                )}
              </span>
            </button>

            {/* Raw error display */}
            {rawOutput && !audit && (
              <div className="bg-rose-950/20 border border-rose-900/40 rounded-xl p-4 text-xs text-rose-400 font-mono whitespace-pre-wrap">
                {rawOutput}
              </div>
            )}
          </div>

          {/* Right: Tabbed Report */}
          <div className="space-y-3">
            {/* Tab Bar */}
            <div className="flex gap-2 flex-wrap bg-slate-900/60 border border-slate-800/60 rounded-xl p-2">
              <TabBtn
                active={activeTab === "executive"}
                onClick={() => setActiveTab("executive")}
                icon="📋"
                label="Executive Summary"
              />
              <TabBtn
                active={activeTab === "vulns"}
                onClick={() => setActiveTab("vulns")}
                icon="🔍"
                label="Vulnerabilities"
                badge={audit ? audit.counts.critical + audit.counts.high : undefined}
              />
              <TabBtn
                active={activeTab === "redteam"}
                onClick={() => setActiveTab("redteam")}
                icon="☠️"
                label="Red Team Sim"
              />
              <TabBtn
                active={activeTab === "remediation"}
                onClick={() => setActiveTab("remediation")}
                icon="🩹"
                label="Remediation"
              />
            </div>

            {/* Tab Content */}
            <div
              className="rounded-xl border overflow-y-auto p-5"
              style={{
                minHeight: "530px",
                maxHeight: "600px",
                background: audit ? "linear-gradient(135deg, #09101f 0%, #080e1c 100%)" : "transparent",
                borderColor: audit ? "rgba(6,182,212,0.15)" : "rgba(51,65,85,0.5)",
                borderStyle: audit ? "solid" : "dashed",
              }}
            >
              {!audit && !isAnalyzing && (
                <div className="h-full flex flex-col items-center justify-center gap-4 text-slate-700 min-h-[480px]">
                  <svg className="w-16 h-16 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={0.75} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  <p className="text-sm">Awaiting contract payload...</p>
                  <p className="text-xs text-slate-800">Paste Solidity code → Initiate scan</p>
                </div>
              )}

              {isAnalyzing && (
                <div className="h-full flex flex-col items-center justify-center gap-6 min-h-[480px]">
                  <div className="relative w-20 h-20">
                    <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20 animate-ping" />
                    <div className="absolute inset-2 rounded-full border-2 border-cyan-500/40 animate-ping" style={{ animationDelay: "0.3s" }} />
                    <div className="absolute inset-4 rounded-full bg-cyan-500/10 border border-cyan-400/50 flex items-center justify-center text-2xl">
                      🔍
                    </div>
                  </div>
                  <p className="text-cyan-400/70 text-xs animate-pulse">{statusMsg}</p>
                </div>
              )}

              {audit && activeTab === "executive" && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="text-lg">📋</span>
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider">Executive Summary</h3>
                    <span
                      className={`ml-auto text-[10px] font-bold px-2 py-1 rounded-full border ${
                        audit.riskScore >= 75
                          ? "bg-rose-950/50 border-rose-700/50 text-rose-400"
                          : audit.riskScore >= 50
                          ? "bg-orange-950/50 border-orange-700/50 text-orange-400"
                          : audit.riskScore >= 25
                          ? "bg-yellow-950/50 border-yellow-700/50 text-yellow-400"
                          : "bg-emerald-950/50 border-emerald-700/50 text-emerald-400"
                      }`}
                    >
                      Risk Score: {audit.riskScore}/100
                    </span>
                  </div>
                  <MarkdownBlock content={audit.executive} />
                </div>
              )}

              {audit && activeTab === "vulns" && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="text-lg">🔍</span>
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider">Vulnerability Details</h3>
                  </div>
                  <MarkdownBlock content={audit.vulnerabilities} />
                </div>
              )}

              {audit && activeTab === "redteam" && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="text-lg">☠️</span>
                    <h3 className="text-sm font-bold text-rose-400 uppercase tracking-wider">Red Team Attack Simulation</h3>
                  </div>
                  <div className="bg-rose-950/10 border border-rose-900/30 rounded-lg p-3 text-xs text-rose-400/80 mb-4">
                    ⚠️ FOR AUTHORIZED SECURITY RESEARCH ONLY
                  </div>
                  <MarkdownBlock content={audit.redTeam} />
                </div>
              )}

              {audit && activeTab === "remediation" && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="text-lg">🩹</span>
                    <h3 className="text-sm font-bold text-emerald-400 uppercase tracking-wider">Remediation Plan</h3>
                  </div>
                  <MarkdownBlock content={audit.remediation} />
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Footer ── */}
        <footer className="border-t border-slate-800/50 pt-4 flex flex-col sm:flex-row justify-between items-center gap-2 text-[10px] text-slate-700">
          <span>SmartGuard_OS v2.0 — Dev3pack Hackathon Build</span>
          <span>Powered by Gemini 2.5 Flash · Next.js App Router · Tailwind CSS</span>
        </footer>
      </div>
    </div>
  );
}
