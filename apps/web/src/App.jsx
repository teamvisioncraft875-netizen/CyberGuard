import React, { useEffect, useState } from 'react';
import { ShieldCheck, Activity, Terminal } from 'lucide-react';

export default function App() {
  const [backendHealth, setBackendHealth] = useState('checking...');
  const [mlHealth, setMlHealth] = useState('checking...');

  useEffect(() => {
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => setBackendHealth(data.status))
      .catch(() => setBackendHealth('offline'));

    fetch('http://localhost:8000/health')
      .then((res) => res.json())
      .then((data) => setMlHealth(data.status))
      .catch(() => setMlHealth('offline'));
  }, []);

  return (
    <div className="min-h-screen bg-cyber-dark text-slate-100 flex flex-col items-center justify-center p-6">
      <div className="max-w-xl w-full bg-cyber-panel/80 border border-slate-800 rounded-2xl p-8 backdrop-blur-md shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyber-accent">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              CYBERGUARD <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-400 font-mono">v0.1.0</span>
            </h1>
            <p className="text-sm text-slate-400">Security Command & Incident Triage Platform</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-slate-900/60 rounded-xl border border-slate-800/80">
            <div className="flex items-center gap-3">
              <Activity className="w-5 h-5 text-emerald-400" />
              <span className="text-sm font-medium">Node.js Gateway (/api/health)</span>
            </div>
            <span className="font-mono text-xs uppercase px-2.5 py-1 rounded-md bg-slate-800 text-slate-300">
              {backendHealth}
            </span>
          </div>

          <div className="flex items-center justify-between p-4 bg-slate-900/60 rounded-xl border border-slate-800/80">
            <div className="flex items-center gap-3">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <span className="text-sm font-medium">FastAPI Engine (:8000/health)</span>
            </div>
            <span className="font-mono text-xs uppercase px-2.5 py-1 rounded-md bg-slate-800 text-slate-300">
              {mlHealth}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
