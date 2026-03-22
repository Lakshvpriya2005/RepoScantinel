
import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { 
  History, 
  Github, 
  Calendar, 
  ChevronRight, 
  Search,
  Filter,
  ArrowUpRight,
  ShieldCheck,
  AlertTriangle,
  Loader2
} from 'lucide-react';

const API_BASE_URL = 'http://localhost:5000/api/v1';

interface ScanRecord {
  id: string;
  repo_url: string;
  repo_name?: string;
  branch: string;
  status: string;
  created_at: string;
  completed_at?: string;
  risk_score?: number;
  classification?: string;
  total_findings?: number;
  critical_count?: number;
}

const ScanHistory: React.FC = () => {
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [filtered, setFiltered] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const { isAuthenticated, token } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
      return;
    }
    fetchMyScans();
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    const q = search.toLowerCase();
    setFiltered(
      q ? history.filter(s => s.repo_url.toLowerCase().includes(q) || (s.repo_name || '').toLowerCase().includes(q)) : history
    );
  }, [search, history]);

  const fetchMyScans = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE_URL}/scans/mine`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Failed to load scan history');
      const data: ScanRecord[] = await res.json();
      setHistory(data);
      setFiltered(data);
    } catch (e: any) {
      setError(e.message || 'Could not load scan history');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score: number = 0) => {
    if (score >= 70) return 'text-red-500';
    if (score >= 40) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getRiskBg = (score: number = 0) => {
    if (score >= 70) return 'bg-red-500/10 border-red-500/20';
    if (score >= 40) return 'bg-yellow-500/10 border-yellow-500/20';
    return 'bg-green-500/10 border-green-500/20';
  };

  const getRepoName = (scan: ScanRecord): string => {
    if (scan.repo_name) return scan.repo_name;
    try {
      const parts = scan.repo_url.replace(/\.git$/, '').split('/');
      return parts[parts.length - 1] || scan.repo_url;
    } catch { return scan.repo_url; }
  };

  const formatDate = (dateStr: string) => {
    try { return new Date(dateStr).toLocaleString(); }
    catch { return dateStr; }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed': return <span className="px-2 py-1 rounded text-xs font-bold bg-emerald-500/20 text-emerald-400">Completed</span>;
      case 'failed':    return <span className="px-2 py-1 rounded text-xs font-bold bg-red-500/20 text-red-400">Failed</span>;
      default:          return <span className="px-2 py-1 rounded text-xs font-bold bg-yellow-500/20 text-yellow-400 capitalize">{status}</span>;
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-12 gap-6">
        <div className="flex items-center space-x-4">
          <div className="w-16 h-16 bg-cyan-500/10 rounded-2xl flex items-center justify-center border border-cyan-500/20">
            <History className="w-8 h-8 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-4xl font-black text-white tracking-tight">My Scan History</h1>
            <p className="text-gray-400 font-medium">All repository analyses from your account.</p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="relative group">
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search repositories..."
              className="bg-white/5 border border-white/10 rounded-xl px-12 py-3 text-sm text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50 transition-all w-64"
            />
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 group-focus-within:text-cyan-400 transition-colors" />
          </div>
          <button
            onClick={fetchMyScans}
            className="p-3 bg-white/5 border border-white/10 rounded-xl hover:bg-cyan-500/10 hover:border-cyan-500/30 transition-all text-gray-400 hover:text-cyan-400"
            title="Refresh"
          >
            <Filter className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-24 text-gray-400 gap-3">
          <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
          <span className="text-lg font-medium">Loading your scan history…</span>
        </div>
      )}

      {/* Error */}
      {!loading && error && (
        <div className="dashboard-card rounded-3xl p-10 flex flex-col items-center text-center border border-red-500/20">
          <AlertTriangle className="w-12 h-12 text-red-400 mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Failed to Load History</h2>
          <p className="text-gray-500 mb-6">{error}</p>
          <button
            onClick={fetchMyScans}
            className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-[#0b111e] font-black rounded-xl transition-all"
          >
            Retry
          </button>
        </div>
      )}

      {/* History List */}
      {!loading && !error && (
        <div className="space-y-4">
          {filtered.map((scan) => (
            scan.status === 'completed' ? (
              <Link
                key={scan.id}
                to={`/dashboard/${scan.id}?url=${encodeURIComponent(scan.repo_url)}`}
                className="block dashboard-card rounded-3xl p-6 hover:bg-white/[0.04] transition-all border border-white/5 hover:border-cyan-500/30 group"
              >
                <ScanRow scan={scan} getRepoName={getRepoName} formatDate={formatDate} getRiskBg={getRiskBg} getRiskColor={getRiskColor} getStatusBadge={getStatusBadge} />
              </Link>
            ) : (
              <div
                key={scan.id}
                className="dashboard-card rounded-3xl p-6 border border-white/5 opacity-80"
              >
                <ScanRow scan={scan} getRepoName={getRepoName} formatDate={formatDate} getRiskBg={getRiskBg} getRiskColor={getRiskColor} getStatusBadge={getStatusBadge} />
              </div>
            )
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && filtered.length === 0 && (
        <div className="dashboard-card rounded-[3rem] p-20 flex flex-col items-center text-center border-dashed border-white/10">
          <ShieldCheck className="w-20 h-20 text-gray-700 mb-6" />
          <h2 className="text-2xl font-bold text-white mb-2">
            {search ? 'No matching scans' : 'No Scan History Found'}
          </h2>
          <p className="text-gray-500 max-w-md mb-8">
            {search
              ? `No scans matching "${search}". Try a different search term.`
              : "You haven't scanned any repositories yet. Start your first analysis!"
            }
          </p>
          <Link to="/scan" className="px-8 py-4 bg-cyan-500 hover:bg-cyan-400 text-[#0b111e] font-black rounded-2xl transition-all shadow-lg">
            Launch New Scan
          </Link>
        </div>
      )}
    </div>
  );
};

// \u2500\u2500 Row sub-component \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
interface ScanRowProps {
  scan: ScanRecord;
  getRepoName: (s: ScanRecord) => string;
  formatDate: (d: string) => string;
  getRiskBg: (n: number) => string;
  getRiskColor: (n: number) => string;
  getStatusBadge: (s: string) => React.ReactNode;
}

const ScanRow: React.FC<ScanRowProps> = ({ scan, getRepoName, formatDate, getRiskBg, getRiskColor, getStatusBadge }) => (
  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 overflow-hidden">
    {/* Repo Info */}
    <div className="flex items-center space-x-5 flex-grow min-w-0">
      <div className="w-14 h-14 bg-black/40 rounded-2xl flex items-center justify-center border border-white/10 group-hover:border-cyan-500/50 transition-colors flex-shrink-0">
        <Github className="w-7 h-7 text-gray-400 group-hover:text-cyan-400 transition-colors" />
      </div>
      <div className="min-w-0 flex-1">
        <h3 className="text-xl font-bold text-white group-hover:text-cyan-400 transition-colors flex items-center truncate">
          <span className="truncate">{getRepoName(scan)}</span>
          <ArrowUpRight className="w-4 h-4 ml-2 opacity-0 group-hover:opacity-100 transition-all flex-shrink-0" />
        </h3>
        <p className="text-gray-500 text-sm font-mono truncate max-w-sm">{scan.repo_url}</p>
      </div>
    </div>

    {/* Stats Grid */}
    <div className="grid grid-cols-2 md:grid-cols-4 gap-6 lg:gap-10 items-center flex-shrink-0">
      {/* Date */}
      <div className="flex flex-col">
        <span className="text-[10px] font-black uppercase tracking-widest text-gray-500 mb-1">Scanned</span>
        <div className="flex items-center text-gray-300 font-bold text-sm">
          <Calendar className="w-4 h-4 mr-2 text-cyan-400/60" />
          {formatDate(scan.created_at)}
        </div>
      </div>

      {/* Status / Findings */}
      <div className="flex flex-col">
        <span className="text-[10px] font-black uppercase tracking-widest text-gray-500 mb-1">Status</span>
        <div>{getStatusBadge(scan.status)}</div>
      </div>

      {/* Findings count */}
      <div className="flex flex-col">
        <span className="text-[10px] font-black uppercase tracking-widest text-gray-500 mb-1">Findings</span>
        <div className="text-white font-bold text-sm">
          {scan.total_findings !== undefined ? (
            <>
              <span className="text-red-400">{scan.critical_count ?? 0} critical</span>
              <span className="text-gray-600 mx-1">/</span>
              <span>{scan.total_findings} total</span>
            </>
          ) : (
            <span className="text-gray-500 italic text-xs">—</span>
          )}
        </div>
      </div>

      {/* Risk Score */}
      <div className="flex flex-col items-start">
        <span className="text-[10px] font-black uppercase tracking-widest text-gray-500 mb-1">Risk Score</span>
        {scan.risk_score !== undefined ? (
          <div className={`px-3 py-1 rounded-full border text-xs font-black ${getRiskBg(scan.risk_score)} ${getRiskColor(scan.risk_score)}`}>
            {scan.risk_score}/100
          </div>
        ) : (
          <span className="text-gray-500 italic text-xs">N/A</span>
        )}
      </div>
    </div>
  </div>
);

export default ScanHistory;
