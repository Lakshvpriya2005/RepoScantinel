
import React from 'react';
import { Link } from 'react-router-dom';
import { Search, ShieldCheck, Zap, Lock, AlertTriangle } from 'lucide-react';

const Home: React.FC = () => {
  return (
    <div className="relative overflow-hidden">
      {/* Hero Section */}
      <section className="relative pt-20 pb-32 px-4">
        <div className="max-w-7xl mx-auto flex flex-col items-center text-center">
          <div className="inline-flex items-center space-x-2 px-4 py-1.5 rounded-full glass-card border-white/20 text-cyan-400 text-sm font-semibold mb-8 animate-bounce">
            <ShieldCheck className="w-4 h-4" />
            <span>Protecting Code Bases Globally</span>
          </div>

          <h1 className="text-6xl md:text-8xl font-black text-white mb-6 tracking-tight">
            Repo<span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-500">Scantinel</span>
          </h1>

          <p className="text-xl md:text-2xl text-gray-300 max-w-3xl mb-12 leading-relaxed">
            Scan GitHub repositories for security vulnerabilities using static analysis tools.
            Identify risks before they hit production.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-6">
            <Link to="/scan" className="group relative px-10 py-5 bg-cyan-500 rounded-full text-white font-bold text-lg hover:bg-cyan-400 transition-all overflow-hidden shadow-[0_0_20px_rgba(34,211,238,0.4)]">
              <span className="relative z-10 flex items-center">
                Start Scanning <Search className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </span>
            </Link>
          </div>

          {/* Floating Elements (Decorative) */}
          <div className="mt-20 w-full max-w-5xl mx-auto glass-card rounded-3xl p-8 border border-white/10 shadow-2xl relative">
            <div className="absolute -top-10 -right-10 w-32 h-32 bg-purple-500/20 rounded-full blur-3xl"></div>
            <div className="absolute -bottom-10 -left-10 w-40 h-40 bg-cyan-500/20 rounded-full blur-3xl"></div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
              <div className="flex flex-col items-center p-4">
                <span className="text-4xl font-black text-white">50k+</span>
                <span className="text-gray-400 text-sm font-medium">Repos Scanned</span>
              </div>
              <div className="flex flex-col items-center p-4">
                <span className="text-4xl font-black text-cyan-400">92.8%</span>
                <span className="text-gray-400 text-sm font-medium">Scan Accuracy</span>
              </div>
              <div className="flex flex-col items-center p-4">
                <span className="text-4xl font-black text-purple-400">15+</span>
                <span className="text-gray-400 text-sm font-medium">Langs Supported</span>
              </div>
              <div className="flex flex-col items-center p-4">
                <span className="text-4xl font-black text-pink-500">24h</span>
                <span className="text-gray-400 text-sm font-medium">Real-time Analysis</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Trust Badges / Stats (Small) */}
      <section className="py-20 bg-black/10 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 grid grid-cols-1 md:grid-cols-3 gap-12">
          <div className="glass-card p-8 rounded-3xl border border-white/10 hover:scale-105 transition-all">
            <Zap className="w-10 h-10 text-yellow-400 mb-4" />
            <h3 className="text-xl font-bold mb-2">Lightning Fast</h3>
            <p className="text-gray-400">Analyzes large codebases in seconds using optimized parsing algorithms.</p>
          </div>
          <div className="glass-card p-8 rounded-3xl border border-white/10 hover:scale-105 transition-all">
            <Lock className="w-10 h-10 text-cyan-400 mb-4" />
            <h3 className="text-xl font-bold mb-2">Secure & Private</h3>
            <p className="text-gray-400">Your code is analyzed locally on our server instance and never stored persistently.</p>
          </div>
          <div className="glass-card p-8 rounded-3xl border border-white/10 hover:scale-105 transition-all">
            <AlertTriangle className="w-10 h-10 text-pink-500 mb-4" />
            <h3 className="text-xl font-bold mb-2">Risk Scoring</h3>
            <p className="text-gray-400">Advanced heuristics to calculate a unified risk score for your entire project.</p>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Home;
