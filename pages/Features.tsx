
import React from 'react';
import { 
  Code2, 
  Target, 
  Layout, 
  ShieldAlert, 
  FileDown, 
  Fingerprint, 
  ShieldCheck, 
  Zap,
  BarChart4
} from 'lucide-react';

const Features: React.FC = () => {
  const features = [
    {
      title: "Multi-Language Repository Scanning",
      desc: "Comprehensive support for Python, JavaScript, TypeScript, Go, Java, and C++ with deep dependency tree analysis.",
      icon: <Code2 className="w-8 h-8 text-cyan-400" />
    },
    {
      title: "Unified Vulnerability Risk Scoring",
      desc: "Our custom proprietary algorithm aggregates all findings into a single, understandable score from 0-100.",
      icon: <Target className="w-8 h-8 text-purple-400" />
    },
    {
      title: "Interactive Vulnerability Dashboard",
      desc: "Filter, search, and drill down into specific vulnerabilities with file paths, line numbers, and impact analysis.",
      icon: <Layout className="w-8 h-8 text-pink-400" />
    },
    {
      title: "Severity-Based Classification",
      desc: "Automatically classifies threats as Critical, High, Medium, or Low based on CVSS metrics and local context.",
      icon: <ShieldAlert className="w-8 h-8 text-yellow-400" />
    },
    {
      title: "PDF & CSV Report Export",
      desc: "Generate professional compliance-ready reports with one click for easy sharing with your dev team.",
      icon: <FileDown className="w-8 h-8 text-teal-400" />
    },
    {
      title: "Privacy-First Local Analysis",
      desc: "Code analysis happens in memory during a secure session. We respect your IP and code confidentiality.",
      icon: <Fingerprint className="w-8 h-8 text-blue-400" />
    }
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 py-20">
      <div className="text-center mb-16">
        <h2 className="text-4xl font-black text-white mb-4">Core Capabilities</h2>
        <div className="w-24 h-1 bg-gradient-to-r from-cyan-500 to-purple-500 mx-auto rounded-full"></div>
        <p className="mt-6 text-gray-400 max-w-2xl mx-auto text-lg">
          Designed specifically for developers and security enthusiasts to maintain high code standards throughout the project lifecycle.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        {features.map((f, i) => (
          <div key={i} className="glass-card p-10 rounded-[2.5rem] border border-white/10 group hover:bg-white/10 transition-all duration-500 hover:-translate-y-2">
            <div className="w-16 h-16 bg-white/5 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
              {f.icon}
            </div>
            <h3 className="text-xl font-bold text-white mb-4">{f.title}</h3>
            <p className="text-gray-400 leading-relaxed">{f.desc}</p>
          </div>
        ))}
      </div>

      {/* Extra Detail Section */}
      <div className="mt-32 glass-card rounded-[3rem] overflow-hidden border border-white/10 p-12">
        <div className="flex flex-col lg:flex-row items-center gap-16">
          <div className="lg:w-1/2">
            <h3 className="text-3xl font-black text-white mb-6">Advanced Security Heuristics</h3>
            <p className="text-gray-400 mb-8 leading-relaxed text-lg">
              RepoScantinel doesn't just look for string matches. We analyze the Abstract Syntax Tree (AST) to find complex vulnerability patterns like SQL Injection, Cross-Site Scripting (XSS), and insecure cryptographic implementations.
            </p>
            <div className="space-y-4">
              <div className="flex items-center space-x-3">
                <ShieldCheck className="w-6 h-6 text-cyan-400" />
                <span className="text-gray-200 font-medium">Pattern-based bug discovery</span>
              </div>
              <div className="flex items-center space-x-3">
                <ShieldCheck className="w-6 h-6 text-cyan-400" />
                <span className="text-gray-200 font-medium">Dependency vulnerability matching (CVE)</span>
              </div>
              <div className="flex items-center space-x-3">
                <ShieldCheck className="w-6 h-6 text-cyan-400" />
                <span className="text-gray-200 font-medium">Secrets & credentials detection</span>
              </div>
            </div>
          </div>
          <div className="lg:w-1/2 relative">
             <div className="w-full aspect-video glass-card rounded-2xl overflow-hidden border border-cyan-500/20 shadow-2xl bg-black/40 p-1">
                <div className="bg-gray-900 w-full h-full rounded-xl p-4 font-mono text-sm text-cyan-300">
                  <div className="flex items-center space-x-2 border-b border-gray-700 pb-2 mb-4">
                    <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                    <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                    <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    <span className="text-gray-500 ml-4">scantinel --repo user/api-gateway</span>
                  </div>
                  <p className="mb-1 text-gray-500">[10:04:12] Initializing engine...</p>
                  <p className="mb-1 text-gray-500">[10:04:13] Cloning repository...</p>
                  <p className="mb-1 text-blue-400">[10:04:15] Analyzing AST (Python)...</p>
                  <p className="mb-1 text-yellow-400">[10:04:18] WARNING: Potential SQLi detected in db_utils.py:42</p>
                  <p className="mb-1 text-red-400">[10:04:19] CRITICAL: Hardcoded AWS secret found in config.yaml:12</p>
                  <p className="mb-1 text-green-400 font-bold">[10:04:22] Analysis Complete. Score: 34/100</p>
                </div>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Features;
