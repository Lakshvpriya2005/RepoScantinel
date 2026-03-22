
import React, { useState, useEffect } from 'react';
import { HashRouter as Router, Routes, Route, Link, useNavigate, useLocation } from 'react-router-dom';
import { 
  ShieldCheck, 
  Search, 
  LayoutDashboard, 
  Mail, 
  LogIn, 
  UserPlus, 
  LogOut, 
  ChevronDown,
  Github,
  AlertTriangle,
  Zap,
  BarChart3,
  Lock,
  FileJson,
  CheckCircle2,
  Menu,
  X
} from 'lucide-react';

// Pages
import Home from './pages/Home';
import Features from './pages/Features';
import Scan from './pages/Scan';
import Dashboard from './pages/Dashboard';
import ScanHistory from './pages/ScanHistory';
import Contact from './pages/Contact';
import Login from './pages/Login';
import Signup from './pages/Signup';
import AdminDashboard from './pages/AdminDashboard';
import { AuthProvider, useAuth } from './context/AuthContext';

// Types
export interface User {
  name: string;
  email: string;
}

const Navbar: React.FC = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const { isAuthenticated, isAdmin, user, logout } = useAuth();
  const location = useLocation();

  const navLinks = [
    { name: 'Home', path: '/' },
    { name: 'Features', path: '/features' },
    { name: 'Scan', path: '/scan' },
    { name: 'History', path: '/history' },
    { name: 'Contact', path: '/contact' },
  ];

  if (isAdmin) {
    navLinks.push({ name: 'Admin Panel', path: '/admin' });
  }

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-transparent backdrop-blur-sm border-b border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-20">
          <Link to="/" className="flex items-center space-x-2 group">
            <div className="p-2 bg-cyan-500/20 rounded-xl border border-cyan-500/30 group-hover:bg-cyan-500/30 transition-all duration-300">
              <ShieldCheck className="w-8 h-8 text-cyan-400" />
            </div>
            <span className="text-2xl font-light text-white">
              Repo<span className="font-extrabold text-cyan-400">Scantinel</span>
            </span>
          </Link>

          {/* Desktop Links */}
          <div className="hidden md:flex items-center space-x-8">
            {navLinks.map((link) => (
              <Link
                key={link.path}
                to={link.path}
                className={`text-sm font-medium transition-colors hover:text-cyan-400 ${
                  location.pathname === link.path ? 'text-cyan-400' : 'text-gray-300'
                }`}
              >
                {link.name}
              </Link>
            ))}

            <div className="pl-4 border-l border-white/10 flex items-center h-8"></div>

            {isAuthenticated ? (
              <div className="flex items-center space-x-6">
                <span className="text-cyan-400 font-bold text-sm tracking-wide flex items-center">
                  <UserPlus className="w-4 h-4 mr-2" /> {user?.name}
                </span>
                <button
                  onClick={logout}
                  className="flex items-center text-sm font-bold text-gray-400 hover:text-red-400 transition-colors"
                >
                  <LogOut className="w-4 h-4 mr-2" /> Sign Out
                </button>
              </div>
            ) : (
              <Link
                to="/login"
                className="px-6 py-2 bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500 text-cyan-400 hover:text-[#0b111e] rounded-xl transition-all font-bold text-sm"
              >
                Sign In
              </Link>
            )}
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden flex items-center">
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="p-2 rounded-md text-gray-400 hover:text-white"
            >
              {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu */}
      {isMenuOpen && (
        <div className="md:hidden glass-card mx-4 rounded-3xl mt-2 py-4 px-6 absolute left-0 right-0 border border-white/10 animate-in slide-in-from-top-4 duration-300">
          <div className="flex flex-col space-y-4">
            {navLinks.map((link) => (
              <Link
                key={link.path}
                to={link.path}
                onClick={() => setIsMenuOpen(false)}
                className="text-lg font-medium text-gray-300 hover:text-cyan-400"
              >
                {link.name}
              </Link>
            ))}
          </div>
        </div>
      )}
    </nav>
  );
};

const App: React.FC = () => {
  return (
    <AuthProvider>
      <Router>
        <AppContent />
      </Router>
    </AuthProvider>
  );
};

const AppContent: React.FC = () => {
  const location = useLocation();
  const isDashboard = location.pathname.includes('/dashboard');

  let bgClass = 'animated-bg';
  if (isDashboard) bgClass = 'solid-bg';

  return (
    <div className={`${bgClass} min-h-screen text-gray-100 selection:bg-cyan-500/30 flex flex-col`}>
      <Navbar />
      <main className="pt-20 flex-grow">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/features" element={<Features />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/dashboard/:scanId" element={<Dashboard />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/admin" element={<AdminDashboard />} />
        </Routes>
      </main>
      
      <footer className="py-20 border-t border-white/5 bg-[#0b111e]">
        <div className="max-w-7xl mx-auto px-4 flex flex-col items-center text-center">
          <div className="flex items-center space-x-2 mb-6">
            <ShieldCheck className="w-10 h-10 text-cyan-400" />
            <span className="text-3xl font-light text-white">
              Repo<span className="font-extrabold text-cyan-400">Scantinel</span>
            </span>
          </div>
          
          <p className="text-gray-400 text-lg max-w-2xl mb-8 leading-relaxed">
            Advanced static analysis for modern development.<br />
            Identifying risks before they reach production.
          </p>
          
          <div className="flex items-center justify-center space-x-12 text-gray-400 mb-12">
            <a href="mailto:lakshvpriya@gmail.com" className="hover:text-white transition-all transform hover:scale-110">
              <Mail className="w-8 h-8" />
            </a>
            <a href="https://github.com/Lakshvpriya2005" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-all transform hover:scale-110">
              <Github className="w-8 h-8" />
            </a>
          </div>

          <div className="w-full border-t border-white/5 pt-8">
            <p className="text-gray-500 text-sm font-medium tracking-wide">
              &copy; 2025 RepoScantinel. All Rights Reserved. | Project by Lakshmipriya V.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
