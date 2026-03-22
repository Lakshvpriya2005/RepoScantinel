
import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
  ShieldCheck, ExternalLink, Calendar, FileText, Database,
  FileDown, TrendingUp, AlertOctagon, ChevronRight,
  BarChart3, Loader2, ShieldAlert, X, Info, ChevronDown,
  ChevronUp, Layers, ToggleLeft, ToggleRight, Wrench
} from 'lucide-react';

const API_BASE = 'http://localhost:5000';

// ─── Types ───────────────────────────────────────────────────────────────────

interface BackendFinding {
  file: string;
  line_number: number;
  severity: string;
  confidence: string;
  issue_text: string;
  test_id: string;
  scanner_source: string;
  scanner?: string;
  owasp?: string | string[];
  cwe?: string;
  fix_recommendation?: string;
  title?: string;
}

interface BackendResult {
  repo_url: string;
  repo_name: string;
  risk_score: number;
  classification: string;
  color: string;
  total_findings: number;
  bandit_count: number;
  semgrep_count: number;
  files_scanned: number;
  lines_of_code: number;
  severity_counts: { HIGH: number; MEDIUM: number; LOW: number; CRITICAL?: number };
  languages: Record<string, number>;
  findings: BackendFinding[];
  findings_per_file: { file: string; count: number }[];
}

interface UIFinding {
  id: number;
  description: string;
  level: string;
  pathway: string;
  file: string;
  scanner: string;
  scanners: string[];   // for dedup — may list multiple
  lineNumber: number;
  testId: string;
  category: string;
  fpRisk: string;
  owasp: string;
  fixSuggestion: string;
}

interface ScanStats {
  repoName: string;
  repoUrl: string;
  scanDate: string;
  filesScanned: number;
  linesOfCode: string;
  riskScore: number;
  totalFindings: number;
  criticalThreats: number;
  banditCount: number;
  semgrepCount: number;
  classification: string;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const STATUS_MSGS: Record<string, string> = {
  pending: 'Initializing scan...',
  running: 'Starting scan...',
  cloning: 'Cloning repository...',
  running_bandit: 'Running Bandit static analysis...',
  running_semgrep: 'Running Semgrep security scan...',
  calculating: 'Calculating risk score...',
};

/** Classify a finding into a category pill */
function deriveCategory(f: BackendFinding): string {
  const id = (f.test_id || '').toLowerCase();
  const text = (f.issue_text || '').toLowerCase();
  const checkId = (f.test_id || '').toLowerCase();  // semgrep check_id style
  const owasp = Array.isArray(f.owasp) ? (f.owasp[0] || '') : (f.owasp || '');
  const combined = id + ' ' + text + ' ' + owasp.toLowerCase() + ' ' + checkId;

  // Specific rule-id overrides first
  if (/b615|hugging.face|huggingface|from.pretrained|revision.*pretrained|supply.chain/.test(combined)) return 'Supply Chain';
  if (/b104|0\.0\.0\.0|host.*0\.0\.0|app.run.*param|misconfigur/.test(combined)) return 'Misconfiguration';

  if (/crypt|hash|md5|sha1|ssl|tls|cipher|rsa|dsa|aes|des/.test(combined)) return 'Crypto';
  if (/sql|inject|exec|eval|shell|command|subprocess|os\.system/.test(combined)) return 'Injection';
  if (/xss|innerHTML|script|mark_safe|markupsafe|markup|jinja|mako|template|safe.filter|unescaped/.test(combined)) return 'XSS';
  if (/bind|socket|network|telnet|ftp|cleartext|interface/.test(combined)) return 'Network';
  if (/secret|password|hardcod|token|key|credential/.test(combined)) return 'Secrets';
  if (/path|traversal|file|directory/.test(combined)) return 'Path Traversal';
  if (/deserializ|pickle|yaml|marshal/.test(combined)) return 'Deserialization';
  return 'Other';
}

/** Estimate false-positive likelihood */
function deriveFPRisk(f: BackendFinding): string {
  const id = (f.test_id || '').toLowerCase();
  const conf = (f.confidence || '').toUpperCase();  // FIXED: was 'LOW', now '' so missing confidence doesn't default to LOW
  // Bandit B-rules that tend to be noisy
  if (/b101|b110|b112|b404|b603|b607/.test(id)) return 'High';
  if (conf === 'HIGH') return 'Low';
  if (conf === 'MEDIUM') return 'Medium';
  if (!conf) return 'Medium';  // ADDED: Semgrep has no confidence field, default to Medium not High
  return 'High';
}

/** Extract a clean OWASP 2021 tag — never returns A00 */
function deriveOWASP(f: BackendFinding, category?: string): string {
  const raw = Array.isArray(f.owasp) ? (f.owasp[0] || '') : (f.owasp || '');
  const id = (f.test_id || '').toUpperCase();

  // Priority 1 — Bandit rule-id EXACT matches (must run before raw value check,
  // because _DEFAULT_KB injects A09 for unknown rules and would shadow these)
  if (id === 'B324') return 'A02:2021';  // SHA1/weak hash
  if (id === 'B303') return 'A02:2021';  // MD5/SHA1 use
  if (id === 'B307') return 'A03:2021';  // eval()
  if (id === 'B102') return 'A03:2021';  // exec()
  if (id === 'B704') return 'A03:2021';  // XSS markupsafe — FIXED: was A09 because raw check ran first
  if (id === 'B615') return 'A08:2021';  // HuggingFace supply chain
  if (id === 'B104') return 'A05:2021';  // Binding to all interfaces

  // Priority 2 — Accept valid OWASP 2021 tag from backend (A01–A10 only)
  const match = raw.match(/A(0[1-9]|10):2021/);
  if (match) return match[0];

  // Priority 3 — Bandit rule-id prefix map
  if (/B30[1-9]|B31[0-9]|B32[0-9]/.test(id)) return 'A02:2021';  // Crypto
  if (/B10[2-9]|B11[0-9]|B60[2-9]|B61[0-9]/.test(id)) return 'A03:2021';  // Injection
  if (/B20[1-9]/.test(id)) return 'A05:2021';                      // Misconfiguration
  if (/B40[1-9]/.test(id)) return 'A06:2021';                      // Vulnerable Components
  if (/B10[5-7]/.test(id)) return 'A04:2021';  // FIXED: hardcoded secrets → A04 Insecure Design (was A07)
  if (/B70[1-3]/.test(id)) return 'A03:2021';                      // XSS → Injection

  // Priority 4 — Derived category fallback (catches Semgrep findings)
  if (category === 'Supply Chain') return 'A08:2021';
  if (category === 'Misconfiguration') return 'A05:2021';
  if (category === 'XSS') return 'A03:2021';
  if (category === 'Injection') return 'A03:2021';
  if (category === 'Crypto') return 'A02:2021';
  if (category === 'Secrets') return 'A04:2021';
  if (category === 'Path Traversal') return 'A01:2021';
  if (category === 'Deserialization') return 'A08:2021';
  if (category === 'Network') return 'A05:2021';
  return 'Unclassified';
}


// ─── Category styles ─────────────────────────────────────────────────────────
const CATEGORY_STYLES: Record<string, string> = {
  'Supply Chain': 'bg-sky-500/15 text-sky-300 border border-sky-500/30',
  Misconfiguration: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
  Crypto: 'bg-purple-500/15 text-purple-300 border border-purple-500/30',
  Injection: 'bg-teal-500/15 text-teal-300 border border-teal-500/30',
  XSS: 'bg-pink-500/15 text-pink-300 border border-pink-500/30',
  Network: 'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  Secrets: 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  'Path Traversal': 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  Deserialization: 'bg-red-500/15 text-red-300 border border-red-500/30',
  Other: 'bg-gray-500/15 text-gray-300 border border-gray-500/30',
};

const FP_STYLES: Record<string, string> = {
  Low: 'bg-green-500/15 text-green-400 border border-green-500/30',
  Medium: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  High: 'bg-red-500/15 text-red-400 border border-red-500/30',
};

const SEV_STYLES: Record<string, { badge: string; dot: string }> = {
  HIGH: { badge: 'bg-red-500/15 text-red-400 border border-red-500/30', dot: 'bg-red-500' },
  MEDIUM: { badge: 'bg-amber-500/15 text-amber-400 border border-amber-500/30', dot: 'bg-amber-500' },
  LOW: { badge: 'bg-green-500/15 text-green-400 border border-green-500/30', dot: 'bg-green-500' },
  CRITICAL: { badge: 'bg-red-700/20 text-red-300 border border-red-700/40', dot: 'bg-red-700' },
};

// ─── Component ────────────────────────────────────────────────────────────────

const Dashboard: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [statusMsg, setStatusMsg] = useState('Loading results...');
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [severityData, setSeverityData] = useState<{ name: string; value: number; color: string }[]>([]);
  const [languageData, setLanguageData] = useState<{ name: string; value: number; color: string }[]>([]);
  const [results, setResults] = useState<UIFinding[]>([]);

  // Table UI state
  const [filterLevel, setFilterLevel] = useState<string>('ALL');
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<UIFinding | null>(null);
  const [showAllFindings, setShowAllFindings] = useState(false);
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const [mergeDuplicates, setMergeDuplicates] = useState(false);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const stopPolling = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };

  // Map backend → UI
  const processResult = (r: BackendResult) => {
    const sevColors: Record<string, string> = {
      HIGH: '#ef4444', MEDIUM: '#f97316', LOW: '#22c55e', CRITICAL: '#dc2626'
    };
    const langColors = ['#22d3ee', '#a78bfa', '#0f766e', '#c2410c', '#ec4899'];

    setStats({
      repoName: r.repo_name,
      repoUrl: r.repo_url,
      scanDate: new Date().toLocaleDateString(),
      filesScanned: r.files_scanned,
      linesOfCode: r.lines_of_code.toLocaleString(),
      riskScore: Math.round(r.risk_score),
      totalFindings: r.total_findings,
      criticalThreats: r.severity_counts.HIGH || 0,
      banditCount: r.bandit_count,
      semgrepCount: r.semgrep_count,
      classification: r.classification,
      highCount: r.severity_counts.HIGH || 0,
      mediumCount: r.severity_counts.MEDIUM || 0,
      lowCount: r.severity_counts.LOW || 0,
    });

    setSeverityData([
      { name: 'High', value: r.severity_counts.HIGH || 0, color: sevColors.HIGH },
      { name: 'Medium', value: r.severity_counts.MEDIUM || 0, color: sevColors.MEDIUM },
      { name: 'Low', value: r.severity_counts.LOW || 0, color: sevColors.LOW },
    ]);

    setLanguageData(
      Object.entries(r.languages).map(([name, value], i) => ({
        name, value, color: langColors[i % langColors.length]
      }))
    );

    setResults(
      r.findings.map((f, i) => ({
        id: i + 1,
        // Always use the scanner's own issue_text as the primary description.
        // Fall back to title only if issue_text is empty (shouldn't happen).
        description: (f.issue_text || f.title || 'Unknown Issue').slice(0, 180),
        level: f.severity,
        file: f.file || '',
        pathway: f.file ? `${f.file}` : 'unknown',
        lineNumber: f.line_number,
        scanner: f.scanner_source || f.scanner || '',
        scanners: [f.scanner_source || f.scanner || ''],
        testId: f.test_id || '',
        category: deriveCategory(f),
        fpRisk: deriveFPRisk(f),
        // Pass category so OWASP fallback can use it
        owasp: (() => { const cat = deriveCategory(f); return deriveOWASP(f, cat); })(),
        fixSuggestion: f.fix_recommendation || '',
      }))
    );

    const history = JSON.parse(localStorage.getItem('repo_scans') || '[]');
    const updated = history.map((s: any) =>
      s.id === scanId
        ? { ...s, riskScore: Math.round(r.risk_score), criticalFindings: r.severity_counts.HIGH || 0, totalFindings: r.total_findings }
        : s
    );
    localStorage.setItem('repo_scans', JSON.stringify(updated));
  };

  useEffect(() => {
    if (!scanId) { setError('No scan ID provided.'); setLoading(false); return; }

    const poll = async () => {
      try {
        const statusRes = await fetch(`${API_BASE}/api/v1/scan/${scanId}`);
        if (!statusRes.ok) throw new Error('Scan not found');
        const statusData = await statusRes.json();

        if (statusData.status === 'completed') {
          stopPolling();
          const resultsRes = await fetch(`${API_BASE}/api/v1/results/${scanId}`);
          if (!resultsRes.ok) throw new Error('Failed to fetch results');
          const resultData: BackendResult = await resultsRes.json();
          processResult(resultData);
          setLoading(false);
        } else if (statusData.status === 'failed') {
          stopPolling();
          setError(statusData.error || 'Scan failed on the backend.');
          setLoading(false);
        } else {
          setStatusMsg(STATUS_MSGS[statusData.status] || 'Scanning...');
        }
      } catch (err: any) {
        stopPolling();
        setError(`Cannot connect to backend: ${err.message}. Make sure python app.py is running on port 5000.`);
        setLoading(false);
      }
    };

    pollRef.current = setInterval(poll, 2500);
    poll();
    return stopPolling;
  }, [scanId]);

  // Merge duplicates logic: group by same description (first 90 chars) + file + line
  const dedupedResults = React.useMemo(() => {
    if (!mergeDuplicates) return results;
    const seen = new Map<string, UIFinding>();
    for (const f of results) {
      const key = `${f.description.slice(0, 90)}|||${f.file}|||${f.lineNumber}`;
      if (!seen.has(key)) {
        seen.set(key, { ...f, scanners: [f.scanner] });
      } else {
        const existing = seen.get(key)!;
        // Promote to highest severity
        const sevOrder: Record<string, number> = { HIGH: 0, CRITICAL: 0, MEDIUM: 1, LOW: 2 };
        if ((sevOrder[f.level] ?? 3) < (sevOrder[existing.level] ?? 3)) {
          existing.level = f.level;
        }
        // Combine scanner sources
        if (!existing.scanners.includes(f.scanner)) {
          existing.scanners = [...existing.scanners, f.scanner];
          existing.scanner = existing.scanners.join(' + ');
        }
      }
    }
    return Array.from(seen.values());
  }, [results, mergeDuplicates]);

  const toggleRow = (id: number) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  // ─── PDF ──────────────────────────────────────────────────────────────────
  const handleDownloadPDF = async () => {
    if (!stats) return;
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();   // 210 mm
    const pageHeight = doc.internal.pageSize.getHeight();  // 297 mm
    const ml = 15; // margin left
    const mr = pageWidth - 15; // margin right

    // ── Dark header banner ──────────────────────────────────────────────────
    doc.setFillColor(11, 17, 30);
    doc.rect(0, 0, pageWidth, 46, 'F');

    // Title: cyan
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(20);
    doc.setTextColor(34, 211, 238);
    doc.text('RepoScantinel Security Report', ml, 28);

    // Generated timestamp: white, right-aligned
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(255, 255, 255);
    doc.text(`Generated: ${new Date().toLocaleString()}`, mr, 28, { align: 'right' });

    // ── Repo name + URL ─────────────────────────────────────────────────────
    let y = 62;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(18);
    doc.setTextColor(10, 10, 10);
    doc.text(stats.repoName, ml, y);

    y += 8;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(80, 80, 80);
    doc.text(`URL: ${stats.repoUrl}`, ml, y);

    // ── Divider ─────────────────────────────────────────────────────────────
    y += 10;
    doc.setDrawColor(220, 220, 220);
    doc.setLineWidth(0.4);
    doc.line(ml, y, mr, y);

    // ── Analysis Summary heading ─────────────────────────────────────────────
    y += 10;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(10, 10, 10);
    doc.text('Analysis Summary', ml, y);

    // ── Two-column stats ────────────────────────────────────────────────────
    y += 10;
    const col2 = ml + 90;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(30, 30, 30);

    const rows2col: [string, string][] = [
      [`Risk Score: ${stats.riskScore}/100 (${stats.classification})`, `Files Scanned: ${stats.filesScanned}`],
      [`Total Findings: ${stats.totalFindings}`, `Lines of Code: ${stats.linesOfCode}`],
      [`High Severity: ${stats.highCount}`, `Bandit: ${stats.banditCount}  Semgrep: ${stats.semgrepCount}`],
      [`Medium Severity: ${stats.mediumCount}`, `Low Severity: ${stats.lowCount}`],
    ];

    for (const [left, right] of rows2col) {
      doc.text(left, ml, y);
      doc.text(right, col2, y);
      y += 7;
    }

    // ── Divider ─────────────────────────────────────────────────────────────
    y += 4;
    doc.line(ml, y, mr, y);
    y += 8;

    // ── Findings heading ────────────────────────────────────────────────────
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(10, 10, 10);
    doc.text('Detected Vulnerabilities', ml, y);
    y += 6;

    // ── Findings table ───────────────────────────────────────────────────────
    autoTable(doc, {
      startY: y,
      head: [['Issue', 'Severity', 'File', 'Line', 'Category', 'OWASP', 'Test ID', 'Scanner', 'Fix Suggestion']],
      body: dedupedResults.map(r => [
        r.description,
        r.level,
        r.pathway,
        String(r.lineNumber),
        r.category,
        r.owasp,
        r.testId || '—',
        r.scanner,
        r.fixSuggestion || '—',
      ]),
      headStyles: {
        fillColor: [11, 17, 30],
        textColor: [34, 211, 238],
        fontStyle: 'bold',
        fontSize: 7,
      },
      styles: {
        fontSize: 6.5,
        cellPadding: 2.5,
        overflow: 'linebreak',
      },
      columnStyles: {
        0: { cellWidth: 38 },  // Issue
        1: { cellWidth: 14 },  // Severity
        2: { cellWidth: 28 },  // File
        3: { cellWidth: 8 },  // Line
        4: { cellWidth: 16 },  // Category
        5: { cellWidth: 14 },  // OWASP
        6: { cellWidth: 14 },  // Test ID
        7: { cellWidth: 14 },  // Scanner
        8: { cellWidth: 44 },  // Fix Suggestion
      },
      alternateRowStyles: { fillColor: [248, 248, 248] },
      didParseCell: (data) => {
        // Colour-code severity column
        if (data.column.index === 1 && data.section === 'body') {
          const sev = String(data.cell.raw).toUpperCase();
          data.cell.styles.fontStyle = 'bold';
          if (sev === 'HIGH') data.cell.styles.textColor = [220, 38, 38];
          if (sev === 'MEDIUM') data.cell.styles.textColor = [217, 119, 6];
          if (sev === 'LOW') data.cell.styles.textColor = [22, 163, 74];
        }
      },
      // Footer with page numbers
      didDrawPage: (data) => {
        const pageCount = (doc as any).internal.getNumberOfPages();
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(150, 150, 150);
        doc.text(
          `RepoScantinel — ${stats.repoName} — Page ${data.pageNumber} of ${pageCount}`,
          pageWidth / 2,
          pageHeight - 8,
          { align: 'center' }
        );
      },
    });

    doc.save(`${stats.repoName}_security_report.pdf`);
  };

  // ─── CSV ──────────────────────────────────────────────────────────────────
  const handleDownloadCSV = () => {
    if (!stats) return;
    const header = ['Issue', 'Severity', 'File', 'Line', 'Scanner', 'Category', 'FP Risk', 'OWASP', 'Fix Suggestion'];
    const rows = dedupedResults.map(r => [
      `"${r.description}"`, r.level, `"${r.pathway}"`, String(r.lineNumber),
      r.scanner, r.category, r.fpRisk, r.owasp, `"${r.fixSuggestion}"`
    ]);
    const csv = [header.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${stats.repoName}_findings.csv`;
    link.click();
  };

  // ─── Loading ──────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center text-center px-4">
        <div className="relative w-24 h-24 mb-8">
          <Loader2 className="w-24 h-24 text-cyan-400 animate-spin absolute inset-0 opacity-20" />
          <Loader2 className="w-24 h-24 text-cyan-400 animate-spin absolute inset-0" style={{ animationDuration: '2s' }} />
          <ShieldAlert className="w-10 h-10 text-cyan-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 animate-pulse" />
        </div>
        <h2 className="text-3xl font-black text-white mb-4">Generating Security Report</h2>
        <p className="text-gray-400 max-w-md font-medium leading-relaxed">{statusMsg}</p>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center text-center px-4">
        <AlertOctagon className="w-20 h-20 text-red-500 mb-6" />
        <h2 className="text-3xl font-black text-white mb-4">Analysis Error</h2>
        <p className="text-gray-400 max-w-md mb-8">{error || 'An unexpected error occurred.'}</p>
        <button onClick={() => navigate('/scan')} className="px-8 py-4 bg-cyan-500 hover:bg-cyan-400 text-[#0b111e] font-black rounded-2xl transition-all">
          New Scan
        </button>
      </div>
    );
  }

  // ─── Filter + paginate ────────────────────────────────────────────────────
  const filteredResults = dedupedResults.filter(item => filterLevel === 'ALL' || item.level === filterLevel);
  const displayResults = showAllFindings ? filteredResults : filteredResults.slice(0, 10);
  const riskColor = stats.riskScore >= 70 ? 'text-red-400' : stats.riskScore >= 40 ? 'text-yellow-400' : 'text-green-400';

  return (
    <div className="max-w-7xl mx-auto px-6 py-12 relative">

      {/* ── Detail Modal ───────────────────────────────────────────────────── */}
      {selectedFinding && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="dashboard-card w-full max-w-2xl rounded-[2.5rem] p-10 border border-white/10 shadow-2xl relative">
            <button onClick={() => setSelectedFinding(null)} className="absolute top-8 right-8 p-2 bg-white/5 rounded-full hover:bg-white/10 transition-all text-gray-400 hover:text-white">
              <X className="w-6 h-6" />
            </button>
            <div className="flex items-center space-x-4 mb-8">
              <div className={`w-14 h-14 rounded-2xl flex items-center justify-center ${selectedFinding.level === 'HIGH' ? 'bg-red-500/10 text-red-500'
                : selectedFinding.level === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-500'
                  : 'bg-green-500/10 text-green-400'}`}>
                <AlertOctagon className="w-8 h-8" />
              </div>
              <div>
                <h3 className="text-xl font-black text-white">{selectedFinding.description}</h3>
                <span className={`text-[10px] font-black uppercase tracking-widest ${selectedFinding.level === 'HIGH' ? 'text-red-500'
                  : selectedFinding.level === 'MEDIUM' ? 'text-yellow-500'
                    : 'text-green-400'}`}>
                  {selectedFinding.level} SEVERITY
                </span>
              </div>
            </div>
            <div className="space-y-6">
              <div>
                <h4 className="text-gray-500 text-xs font-black uppercase tracking-widest mb-2">File Pathway</h4>
                <div className="bg-black/40 p-4 rounded-xl border border-white/5 font-mono text-cyan-400 text-sm">
                  {selectedFinding.pathway} : {selectedFinding.lineNumber}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <h4 className="text-gray-500 text-xs font-black uppercase tracking-widest mb-2">Scanner</h4>
                  <p className="text-gray-300 text-sm font-mono">{selectedFinding.scanner.toUpperCase()}</p>
                </div>
                <div>
                  <h4 className="text-gray-500 text-xs font-black uppercase tracking-widest mb-2">Rule ID</h4>
                  <p className="text-cyan-400 font-mono text-sm">{selectedFinding.testId || 'N/A'}</p>
                </div>
                <div>
                  <h4 className="text-gray-500 text-xs font-black uppercase tracking-widest mb-2">Category</h4>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold ${CATEGORY_STYLES[selectedFinding.category] || CATEGORY_STYLES.Other}`}>
                    {selectedFinding.category}
                  </span>
                </div>
                <div>
                  <h4 className="text-gray-500 text-xs font-black uppercase tracking-widest mb-2">OWASP</h4>
                  <p className="text-cyan-400 font-mono text-sm">{selectedFinding.owasp}</p>
                </div>
              </div>
              {selectedFinding.fixSuggestion && (
                <div>
                  <h4 className="text-gray-500 text-xs font-black uppercase tracking-widest mb-2 flex items-center gap-2">
                    <Wrench className="w-3.5 h-3.5 text-cyan-400" /> Fix Suggestion
                  </h4>
                  <div className="bg-black/40 p-4 rounded-xl border border-cyan-500/10 text-gray-300 text-sm leading-relaxed">
                    {selectedFinding.fixSuggestion}
                  </div>
                </div>
              )}
            </div>
            <div className="mt-10 pt-8 border-t border-white/5 flex justify-end">
              <button onClick={() => setSelectedFinding(null)} className="px-8 py-3 bg-cyan-500 hover:bg-cyan-400 text-[#0b111e] font-black rounded-xl transition-all">
                Acknowledge
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="dashboard-card rounded-[2rem] p-10 mb-8 flex flex-col md:flex-row justify-between items-start md:items-center">
        <div>
          <h1 className="text-5xl font-extrabold text-white flex items-center mb-4">
            {stats.repoName}
            <a href={stats.repoUrl} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="ml-4 w-6 h-6 text-cyan-400 cursor-pointer hover:scale-110 transition-transform" />
            </a>
          </h1>
          <div className="flex flex-wrap items-center gap-8 text-gray-400 text-sm font-semibold uppercase tracking-wider">
            <div className="flex items-center"><Calendar className="w-5 h-5 mr-2 text-cyan-400" />{stats.scanDate}</div>
            <div className="flex items-center"><FileText className="w-5 h-5 mr-2 text-purple-400" />{stats.filesScanned} Files</div>
            <div className="flex items-center"><Database className="w-5 h-5 mr-2 text-teal-400" />{stats.linesOfCode} LOC</div>
          </div>
        </div>
        <div className="flex space-x-4 mt-8 md:mt-0">
          <button onClick={() => navigate('/scan')} className="flex items-center px-8 py-4 bg-transparent border border-cyan-500/40 hover:border-cyan-400 text-cyan-400 hover:text-cyan-300 rounded-2xl transition-all font-bold">
            <ShieldCheck className="w-5 h-5 mr-2" /> New Scan
          </button>
          <button onClick={handleDownloadPDF} className="flex items-center px-8 py-4 bg-transparent border border-gray-700 hover:border-gray-500 text-white rounded-2xl transition-all font-bold">
            <FileDown className="w-5 h-5 mr-2" /> PDF
          </button>
          <button onClick={handleDownloadCSV} className="flex items-center px-8 py-4 bg-cyan-500 hover:bg-cyan-400 text-[#0b111e] rounded-2xl transition-all font-bold shadow-[0_0_30px_rgba(34,211,238,0.2)]">
            <FileDown className="w-5 h-5 mr-2" /> CSV
          </button>
        </div>
      </div>

      {/* ── Metrics ────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
        <div className="dashboard-card rounded-[2.5rem] p-10 relative overflow-hidden">
          <TrendingUp className="w-12 h-12 text-cyan-400 opacity-40 absolute top-6 right-8" />
          <p className="text-gray-400 text-sm font-extrabold uppercase tracking-[0.2em] mb-6 text-center">Risk Score</p>
          <div className="flex flex-col items-center">
            <div className="flex items-baseline">
              <span className={`text-8xl font-black leading-none ${riskColor}`}>{stats.riskScore}</span>
              <span className="text-2xl text-gray-600 font-bold ml-2">/100</span>
            </div>
            <p className={`mt-6 text-sm font-black tracking-widest uppercase ${riskColor}`}>{stats.classification}</p>
          </div>
        </div>

        <div className="dashboard-card rounded-[2.5rem] p-10 flex flex-col items-center justify-center">
          <p className="text-gray-400 text-sm font-extrabold uppercase tracking-[0.2em] mb-6">Total Findings</p>
          <span className="text-9xl font-black text-purple-300 leading-none mb-4">{stats.totalFindings}</span>
          <div className="flex space-x-3 text-xs font-bold">
            <span className="px-3 py-1 bg-cyan-500/10 text-cyan-400 rounded-full">Bandit: {stats.banditCount}</span>
            <span className="px-3 py-1 bg-purple-500/10 text-purple-400 rounded-full">Semgrep: {stats.semgrepCount}</span>
          </div>
        </div>

        <div className="dashboard-card rounded-[2.5rem] p-10 flex flex-col items-center justify-center">
          <p className="text-gray-400 text-sm font-extrabold uppercase tracking-[0.2em] mb-6">High Severity</p>
          <span className="text-9xl font-black text-red-400 leading-none mb-6">
            {stats.criticalThreats < 10 ? `0${stats.criticalThreats}` : stats.criticalThreats}
          </span>
          <div className="flex items-center text-red-400/90 text-sm font-black tracking-widest uppercase">
            <AlertOctagon className="w-5 h-5 mr-2" />
            {stats.criticalThreats > 0 ? 'Immediate Action Required' : 'No High Risks'}
          </div>
        </div>
      </div>

      {/* ── Charts ─────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mb-8">
        <div className="dashboard-card rounded-[2.5rem] p-10 lg:col-span-4 flex flex-col items-center">
          <p className="text-gray-400 text-sm font-extrabold uppercase tracking-[0.2em] mb-8">Language Split</p>
          {languageData.length > 0 ? (
            <>
              <div className="h-[240px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={languageData} cx="50%" cy="50%" innerRadius={65} outerRadius={95} paddingAngle={8} dataKey="value" stroke="none">
                      {languageData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#111827', border: 'none', borderRadius: '12px', fontSize: '12px' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="grid grid-cols-2 gap-x-8 gap-y-3 mt-4">
                {languageData.map((lang, idx) => (
                  <div key={idx} className="flex items-center space-x-2">
                    <div className="w-10 h-3 rounded-sm" style={{ backgroundColor: lang.color }}></div>
                    <span className="text-xs font-bold text-white">{lang.name}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="text-gray-500 text-sm">No language data available</p>
          )}
        </div>

        <div className="dashboard-card rounded-[2.5rem] p-10 lg:col-span-8">
          <div className="flex items-center space-x-3 mb-8">
            <div className="p-2 bg-cyan-500/10 rounded-lg"><BarChart3 className="w-6 h-6 text-cyan-400" /></div>
            <h3 className="text-2xl font-black text-white">Severity Breakdown</h3>
          </div>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} barSize={80}>
                <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="name" stroke="#4b5563" fontSize={12} fontWeight="bold" tickLine={false} axisLine={false} dy={10} />
                <YAxis stroke="#4b5563" fontSize={12} fontWeight="bold" tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: 'rgba(255,255,255,0.02)' }} contentStyle={{ backgroundColor: '#111827', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px' }} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {severityData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ── FINDINGS TABLE ─────────────────────────────────────────────────── */}
      <div className="dashboard-card rounded-[2.5rem] overflow-hidden">

        {/* Table header */}
        <div className="p-8 border-b border-white/5 bg-white/[0.01] space-y-4">

          {/* Title row — buttons on right */}
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center space-x-4">
              <div className="w-12 h-12 bg-cyan-500/10 rounded-2xl flex items-center justify-center">
                <ShieldCheck className="w-7 h-7 text-cyan-400" />
              </div>
              <h3 className="text-3xl font-black text-white tracking-tight">Detected Vulnerabilities</h3>
            </div>

            <div className="flex items-center gap-3">
              {/* Merge Duplicates toggle */}
              <button
                onClick={() => setMergeDuplicates(prev => !prev)}
                title="Merge findings with the same issue at the same file+line across both scanners"
                className={`flex items-center gap-2 px-5 py-3 rounded-xl font-bold text-sm transition-all border ${mergeDuplicates
                  ? 'bg-violet-500/20 border-violet-500/40 text-violet-300 shadow-[0_0_15px_rgba(139,92,246,0.2)]'
                  : 'bg-white/5 border-white/5 hover:bg-white/10 text-gray-400 hover:text-gray-200'
                  }`}
              >
                <Layers className="w-4 h-4" />
                Merge Dupes
                {mergeDuplicates && (
                  <span className="ml-1 px-1.5 py-0.5 bg-violet-400/20 text-violet-300 text-[10px] font-black rounded-full">
                    {results.length - dedupedResults.length > 0 ? `-${results.length - dedupedResults.length}` : 'ON'}
                  </span>
                )}
              </button>

              {/* Simple dropdown filter */}
              <div className="relative">
                <button
                  onClick={() => setIsFilterOpen(prev => !prev)}
                  className="flex items-center px-6 py-3 bg-white/5 border border-white/5 hover:bg-white/10 rounded-xl transition-all font-bold text-sm text-gray-300"
                >
                  {filterLevel === 'ALL' ? 'All Severity' : filterLevel}
                  <ChevronDown className={`ml-2 w-4 h-4 transition-transform ${isFilterOpen ? 'rotate-180' : ''}`} />
                </button>
                {isFilterOpen && (
                  <div className="absolute right-0 mt-2 w-44 bg-[#111827] border border-white/10 rounded-2xl py-2 shadow-2xl z-50">
                    {(['ALL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(level => (
                      <button
                        key={level}
                        onClick={() => { setFilterLevel(level); setIsFilterOpen(false); }}
                        className={`w-full text-left px-4 py-2 text-sm transition-colors hover:bg-white/5 ${filterLevel === level ? 'text-cyan-400 font-bold' : 'text-gray-400'}`}
                      >
                        {level === 'ALL' ? 'All Severity' : level}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Stats bar */}
          <div className="flex flex-wrap items-center gap-3 text-xs font-bold">
            <span className="text-gray-500 uppercase tracking-widest mr-1">Findings:</span>
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block"></span>
              HIGH &nbsp;{stats.highCount}
            </span>
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 inline-block"></span>
              MEDIUM &nbsp;{stats.mediumCount}
            </span>
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-green-500/10 text-green-400 border border-green-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block"></span>
              LOW &nbsp;{stats.lowCount}
            </span>
            <span className="mx-2 h-4 w-px bg-white/10 inline-block self-center"></span>
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              Bandit &nbsp;{stats.banditCount}
            </span>
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">
              Semgrep &nbsp;{stats.semgrepCount}
            </span>
          </div>
        </div>

        {/* Table itself */}
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-white/[0.02] text-gray-400 text-xs font-black uppercase tracking-[0.14em]">
                <th className="px-6 py-5 w-8"></th>
                <th className="px-4 py-5 text-sm">Issue</th>
                <th className="px-4 py-5 text-center text-sm">Severity</th>
                <th className="px-4 py-5 text-sm">File : Line</th>
                <th className="px-4 py-5 text-sm">Scanner</th>
                <th className="px-4 py-5 text-center text-sm">Category</th>
                <th className="px-4 py-5 text-center text-sm">FP Risk</th>
                <th className="px-4 py-5 text-center text-sm">OWASP</th>
                <th className="px-4 py-5 text-sm">Test ID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {displayResults.map(item => {
                const sevStyle = SEV_STYLES[item.level] || SEV_STYLES.LOW;
                const catStyle = CATEGORY_STYLES[item.category] || CATEGORY_STYLES.Other;
                const fpStyle = FP_STYLES[item.fpRisk] || FP_STYLES.High;
                const expanded = expandedRows.has(item.id);

                return (
                  <React.Fragment key={item.id}>
                    <tr
                      className="hover:bg-white/[0.025] transition-colors group cursor-pointer"
                      onClick={() => toggleRow(item.id)}
                    >
                      {/* Expand indicator */}
                      <td className="px-6 py-5 text-gray-600 group-hover:text-gray-400 transition-colors">
                        {expanded
                          ? <ChevronUp className="w-4 h-4" />
                          : <ChevronRight className="w-4 h-4" />}
                      </td>

                      {/* Issue description — full text, no truncation */}
                      <td className="px-4 py-5 max-w-xs">
                        <span className="text-[15px] font-bold text-white group-hover:text-cyan-300 transition-colors leading-snug">
                          {item.description}
                        </span>
                      </td>

                      {/* Severity badge with dot */}
                      <td className="px-4 py-5 text-center">
                        <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-black uppercase tracking-widest ${sevStyle.badge}`}>
                          <span className={`w-2 h-2 rounded-full ${sevStyle.dot}`}></span>
                          {item.level}
                        </span>
                      </td>

                      {/* File : Line */}
                      <td className="px-4 py-5">
                        <div className="font-mono text-sm text-cyan-400/90 truncate max-w-[220px] font-semibold">{item.pathway}</div>
                        <div className="font-mono text-xs text-gray-400 mt-1 font-bold">Line {item.lineNumber}</div>
                      </td>

                      {/* Scanner */}
                      <td className="px-4 py-5">
                        <span className="text-xs font-bold text-gray-300 uppercase tracking-wide">
                          {item.scanner}
                        </span>
                      </td>

                      {/* Category */}
                      <td className="px-4 py-5 text-center">
                        <span className={`px-3 py-1.5 rounded-full text-xs font-bold ${catStyle}`}>
                          {item.category}
                        </span>
                      </td>

                      {/* FP Risk */}
                      <td className="px-4 py-5 text-center">
                        <span className={`px-3 py-1.5 rounded-full text-xs font-bold ${fpStyle}`}>
                          {item.fpRisk}
                        </span>
                      </td>

                      {/* OWASP */}
                      <td className="px-4 py-5 text-center">
                        <span className="font-mono text-sm text-cyan-400 font-bold tracking-tight">{item.owasp}</span>
                      </td>

                      {/* Test ID */}
                      <td className="px-4 py-5">
                        <span className="font-mono text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 px-2.5 py-1 rounded-lg font-bold">
                          {item.testId || '—'}
                        </span>
                      </td>
                    </tr>

                    {/* Expandable fix suggestion row */}
                    {expanded && (
                      <tr className="bg-[#0a1220]">
                        <td></td>
                        <td colSpan={8} className="px-6 pb-6 pt-4">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                            <div>
                              <p className="text-[10px] font-black uppercase tracking-widest text-cyan-500 mb-2 flex items-center gap-1.5">
                                <Wrench className="w-3 h-3" /> Fix Suggestion
                              </p>
                              <div className="bg-black/40 border border-cyan-500/10 rounded-xl px-4 py-3 text-gray-300 text-sm leading-relaxed min-h-[3rem]">
                                {item.fixSuggestion
                                  ? item.fixSuggestion
                                  : <span className="text-gray-600 italic">No specific fix available — review code context.</span>
                                }
                              </div>
                            </div>
                            <div>
                              <p className="text-[10px] font-black uppercase tracking-widest text-cyan-500 mb-2 flex items-center gap-1.5">
                                <Info className="w-3 h-3" /> Test ID
                              </p>
                              <div className="bg-black/40 border border-white/5 rounded-xl px-4 py-3 font-mono text-cyan-400 text-sm">
                                {item.testId || 'N/A'}
                              </div>
                            </div>
                          </div>
                          <div className="flex justify-end border-t border-white/5 pt-3">
                            <button
                              onClick={e => { e.stopPropagation(); setSelectedFinding(item); }}
                              className="text-xs font-black text-cyan-500 hover:text-cyan-300 uppercase tracking-widest transition-all flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20"
                            >
                              Full Details <ChevronRight className="w-3 h-3" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}

              {displayResults.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-10 py-20 text-center">
                    <Info className="w-12 h-12 text-gray-700 mx-auto mb-4" />
                    <p className="text-gray-500 font-bold">No findings match the selected filter.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Show more / less */}
        <div className="p-8 bg-white/[0.01] border-t border-white/5 flex justify-center">
          <button
            onClick={() => setShowAllFindings(!showAllFindings)}
            className="text-gray-400 font-black text-xs uppercase tracking-[0.3em] hover:text-white transition-all"
          >
            {showAllFindings ? 'Show Less ▲' : `View All ${filteredResults.length} Findings ▼`}
          </button>
        </div>
      </div>

    </div>
  );
};

export default Dashboard;
