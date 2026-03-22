
import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Github,
  Search,
  CheckCircle2,
  Loader2,
  AlertCircle,
  Shield,
  LogIn
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const API_BASE = 'http://localhost:5000';

const STATUS_STEPS: Record<string, number> = {
  pending: 0,
  running: 1,
  cloning: 1,
  running_bandit: 2,
  running_semgrep: 3,
  calculating: 4,
  completed: 5,
  failed: 5,
};

const STEP_LABELS = [
  "Initializing scan",
  "Cloning remote source code",
  "Running Bandit analysis",
  "Running Semgrep analysis",
  "Calculating risk score",
  "Finalizing report",
];

const Scan: React.FC = () => {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [step, setStep] = useState(0);
  const [progress, setProgress] = useState(0);
  const [phaseLabel, setPhaseLabel] = useState('');
  const [error, setError] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const navigate = useNavigate();
  const { token, isAuthenticated } = useAuth();
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  useEffect(() => {
    if (!scanId) return;

    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/scan/${scanId}`);
        const data = await res.json();

        const currentStep = STATUS_STEPS[data.status] ?? 0;
        setStep(currentStep);

        // Use real progress and phase from backend
        if (typeof data.progress === 'number') {
          setProgress(data.progress);
        }
        if (data.phase) {
          setPhaseLabel(data.phase);
        }

        if (data.status === 'completed') {
          setProgress(100);
          stopPolling();
          // Save to scan history
          const newScan = {
            id: scanId,
            repoUrl: url,
            repoName: url.split('/').pop() || 'Unknown Repo',
            date: new Date().toLocaleDateString(),
            status: 'completed',
          };
          const existing = JSON.parse(localStorage.getItem('repo_scans') || '[]');
          localStorage.setItem('repo_scans', JSON.stringify([newScan, ...existing]));
          setTimeout(() => navigate(`/dashboard/${scanId}`), 800);
        } else if (data.status === 'failed') {
          stopPolling();
          setIsScanning(false);
          setError(data.error || 'Scan failed. Please try again.');
        }
      } catch {
        stopPolling();
        setIsScanning(false);
        setError('Cannot reach backend. Make sure python app.py is running on port 5000.');
      }
    };

    pollRef.current = setInterval(poll, 2000);
    poll(); // immediate first call
    return stopPolling;
  }, [scanId]);


  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.includes('github.com')) {
      setError('Please enter a valid GitHub repository URL');
      return;
    }
    setError('');
    setIsScanning(true);
    setStep(0);

    try {
      const res = await fetch(`${API_BASE}/api/v1/scan`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ repo_url: url, branch: 'main' }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `Server error ${res.status}`);
      }
      const data = await res.json();
      setScanId(data.scan_id);
    } catch (err: any) {
      setIsScanning(false);
      setError(err.message || 'Failed to start scan. Is the backend running?');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-20 min-h-[70vh] flex flex-col items-center">
      {!isScanning ? (
        <div className="w-full max-w-5xl space-y-12 flex flex-col items-center">
          {/* Main Scan Card */}
          <div className="w-full dashboard-card rounded-[3rem] p-16 border border-white/5 shadow-2xl relative overflow-hidden flex flex-col items-center">
            <div className="w-28 h-28 bg-[#0b111e] rounded-3xl border border-white/5 flex items-center justify-center mb-10 shadow-inner group">
              <Github className="w-16 h-16 text-cyan-400 transition-transform group-hover:scale-110 duration-500" />
            </div>

            <h1 className="text-6xl font-black text-white mb-6 tracking-tight text-center">Vulnerability Scan</h1>
            <p className="text-gray-400 text-xl font-medium max-w-xl mx-auto text-center mb-12 leading-relaxed opacity-80">
              Input a repository URL to begin the automated static analysis process.
            </p>

            <form onSubmit={handleScan} className="w-full max-w-3xl flex items-stretch">
              <div className="relative flex-grow group">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://github.com/username/project"
                  className="w-full h-16 px-8 rounded-l-2xl bg-black/40 border border-white/10 text-white text-lg focus:outline-none focus:ring-2 focus:ring-cyan-500/50 transition-all pl-16 border-r-0"
                  required
                />
                <Search className="absolute left-6 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-cyan-400 transition-colors w-6 h-6" />
              </div>
              
              {isAuthenticated ? (
                <button
                  type="submit"
                  className="h-16 px-12 bg-cyan-500 hover:bg-cyan-400 text-[#0b111e] font-black rounded-r-2xl transition-all shadow-[0_0_30px_rgba(34,211,238,0.3)] flex items-center text-xl"
                >
                  Launch Analysis
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => navigate('/login')}
                  className="h-16 px-12 bg-gray-600 hover:bg-gray-500 text-white font-black rounded-r-2xl transition-all flex items-center text-xl"
                >
                  <LogIn className="w-5 h-5 mr-2" /> Login
                </button>
              )}
            </form>

            {error && (
              <div className="mt-6 flex items-center text-red-500 space-x-2">
                <AlertCircle className="w-5 h-5 flex-shrink-0" />
                <span className="text-sm font-bold">{error}</span>
              </div>
            )}
          </div>

          {/* Security Disclaimer */}
          <div className="w-full max-w-5xl dashboard-card rounded-[2.5rem] p-12 border border-dashed border-white/10 bg-white/[0.01] flex flex-col items-center">
            <div className="flex items-center space-x-3 mb-6">
              <Shield className="w-7 h-7 text-cyan-400" />
              <h3 className="text-cyan-400 font-black uppercase tracking-[0.3em] text-sm">Security Disclaimer</h3>
            </div>
            <p className="text-gray-400 text-center max-w-3xl leading-relaxed font-semibold">
              RepoScantinel analyzes public GitHub repositories using Bandit and Semgrep.
              The repository is cloned temporarily and deleted after scanning.
            </p>
          </div>
        </div>
      ) : (
        /* Processing View */
        <div className="w-full max-w-2xl dashboard-card p-12 rounded-[3rem] border border-white/10 relative overflow-hidden shadow-[0_0_50px_rgba(34,211,238,0.1)]">
          <div className="scan-line"></div>
          <div className="text-center mb-10 relative z-10">
            <div className="relative w-32 h-32 mx-auto mb-8">
              <Loader2 className="w-32 h-32 text-cyan-400 animate-spin absolute inset-0 opacity-20" />
              <Loader2 className="w-32 h-32 text-cyan-400 animate-spin absolute inset-0" style={{ animationDuration: '3s' }} />
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-xl font-black text-cyan-400">{progress}%</span>
              </div>
            </div>
            <h2 className="text-3xl font-black text-white mb-3">Deep Analysis in Progress</h2>
            <p className="text-gray-500 font-medium">Running real static analysis with Bandit & Semgrep...</p>
            {phaseLabel && (
              <p className="text-cyan-400/70 text-sm font-semibold mt-2 animate-pulse">{phaseLabel}</p>
            )}
          </div>

          <div className="space-y-5 relative z-10 px-6">
            {STEP_LABELS.map((s, i) => (
              <div key={i} className={`flex items-center space-x-4 transition-all duration-500 ${i <= step ? 'opacity-100' : 'opacity-10 translate-x-4'}`}>
                {i < step ? (
                  <CheckCircle2 className="w-6 h-6 text-green-400" />
                ) : i === step ? (
                  <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
                ) : (
                  <div className="w-6 h-6 border-2 border-gray-700 rounded-full"></div>
                )}
                <span className={`text-lg ${i === step ? 'text-white font-black' : 'text-gray-500 font-bold'}`}>{s}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default Scan;
