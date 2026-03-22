import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { Users, Activity, Trash2, ShieldAlert } from 'lucide-react';

const API_BASE_URL = 'http://localhost:5000/api/v1';

const AdminDashboard: React.FC = () => {
  const { user, token, isAdmin } = useAuth();
  const navigate = useNavigate();
  const [usersList, setUsersList] = useState<any[]>([]);
  const [globalScans, setGlobalScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isAdmin) {
      navigate('/history');
      return;
    }

    const fetchAdminData = async () => {
      try {
        const usersRes = await fetch(`${API_BASE_URL}/admin/users`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (usersRes.ok) setUsersList(await usersRes.json());

        const scansRes = await fetch(`${API_BASE_URL}/admin/scans`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (scansRes.ok) setGlobalScans(await scansRes.json());
      } catch (e) {
        console.error('Failed to fetch admin data', e);
      } finally {
        setLoading(false);
      }
    };

    fetchAdminData();
  }, [isAdmin, navigate, token]);

  const handleDeleteUser = async (userId: number) => {
    if (!window.confirm("Are you sure you want to delete this user and all their scans?")) return;
    try {
      const res = await fetch(`${API_BASE_URL}/admin/users/${userId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setUsersList(usersList.filter(u => u.id !== userId));
      } else {
        alert("Cannot delete yourself.");
      }
    } catch (e) {
      console.error(e);
    }
  };

  if (loading) return <div className="p-8 text-center text-gray-400">Loading admin data...</div>;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="flex items-center space-x-4 mb-12">
        <ShieldAlert className="w-10 h-10 text-cyan-400" />
        <h1 className="text-4xl font-bold text-white">Admin Control Panel</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
        <div className="glass-card p-8 rounded-3xl border border-white/5 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-8 opacity-10">
            <Users className="w-32 h-32 text-cyan-400" />
          </div>
          <h3 className="text-sm font-bold tracking-widest text-gray-400 uppercase mb-4">Total Users</h3>
          <div className="text-6xl font-black text-cyan-400 mb-2">{usersList.length}</div>
          <div className="text-sm text-cyan-400/60 font-medium">REGISTERED ON PLATFORM</div>
        </div>
        
        <div className="glass-card p-8 rounded-3xl border border-white/5 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-8 opacity-10">
            <Activity className="w-32 h-32 text-purple-400" />
          </div>
          <h3 className="text-sm font-bold tracking-widest text-gray-400 uppercase mb-4">Total Scans</h3>
          <div className="text-6xl font-black text-purple-400 mb-2">{globalScans.length}</div>
          <div className="text-sm text-purple-400/60 font-medium">SYSTEM-WIDE EXECUTIONS</div>
        </div>
      </div>

      <h2 className="text-2xl font-bold text-white mb-6">User Management</h2>
      <div className="glass-card rounded-2xl border border-white/5 overflow-hidden mb-12">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-[#0b111e]/50 border-b border-gray-800">
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">ID</th>
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">Name</th>
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">Email</th>
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">Role</th>
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">Scans Run</th>
              <th className="p-4 text-right text-xs font-bold tracking-wider text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {usersList.map((usr) => (
              <tr key={usr.id} className="hover:bg-cyan-500/5 transition-colors group">
                <td className="p-4 text-gray-400 font-mono text-sm">{usr.id}</td>
                <td className="p-4 text-white font-medium">{usr.name}</td>
                <td className="p-4 text-gray-400 text-sm">{usr.email}</td>
                <td className="p-4 text-gray-400 text-sm">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${usr.role === 'admin' ? 'bg-purple-500/20 text-purple-400' : 'bg-gray-800 text-gray-300'}`}>
                    {usr.role}
                  </span>
                </td>
                <td className="p-4 text-gray-400 text-sm">{usr.scan_count}</td>
                <td className="p-4 text-right">
                  {usr.role !== 'admin' && (
                    <button
                      onClick={() => handleDeleteUser(usr.id)}
                      className="p-2 bg-red-500/10 text-red-400 hover:bg-red-500 hover:text-white rounded-lg transition-colors opacity-0 group-hover:opacity-100"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="text-2xl font-bold text-white mb-6">Global Scan History</h2>
      <div className="glass-card rounded-2xl border border-white/5 overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-[#0b111e]/50 border-b border-gray-800">
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">Scan ID</th>
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">User Email</th>
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">Repository</th>
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">Status</th>
              <th className="p-4 text-xs font-bold tracking-wider text-gray-500 uppercase">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {globalScans.map((scan) => (
              <tr key={scan.id} className="hover:bg-cyan-500/5 transition-colors">
                <td className="p-4 text-gray-400 font-mono text-xs">{scan.id.substring(0,8)}...</td>
                <td className="p-4 text-cyan-400 text-sm font-medium">{scan.user_email || 'System'}</td>
                <td className="p-4 text-gray-300 text-sm">{scan.repo_url}</td>
                <td className="p-4 text-sm">
                  {scan.status === 'completed' ? (
                    <span className="text-emerald-400">Completed</span>
                  ) : scan.status === 'failed' ? (
                    <span className="text-red-400">Failed</span>
                  ) : (
                    <span className="text-yellow-400 capitalize">{scan.status}</span>
                  )}
                </td>
                <td className="p-4 text-gray-300 text-sm">
                  {new Date(scan.created_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AdminDashboard;
