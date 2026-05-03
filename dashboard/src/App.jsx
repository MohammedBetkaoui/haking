import React, { useState, useEffect, useCallback, useRef } from 'react';
import IncidentList from './components/IncidentList';
import IncidentDetail from './components/IncidentDetail';
import SlaBoard from './components/SlaBoard';
import StatsView from './components/StatsView';
import NetworkScanView from './components/NetworkScanView';
import AgentReportsView from './components/AgentReportsView';
import { connectSocket } from './lib/socket';
import { Shield, BarChart2, List, Siren, Wifi, ShieldAlert, X, Bell, Bot } from 'lucide-react';

// ─── Global Toast Notification System ───────────────────────────────────────

function ToastContainer({ toasts, onDismiss }) {
  if (toasts.length === 0) return null;
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className="pointer-events-auto animate-slide-in flex items-start gap-3 bg-gray-900 border border-red-500/40 rounded-xl shadow-2xl shadow-red-900/30 px-4 py-3"
        >
          {/* pulsing danger icon */}
          <span className="mt-0.5 flex-shrink-0 w-8 h-8 rounded-full bg-red-500/15 flex items-center justify-center">
            <ShieldAlert size={16} className="text-red-400 animate-pulse" />
          </span>

          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-red-300">{t.title}</p>
            <p className="text-xs text-gray-400 mt-0.5 truncate">{t.body}</p>
            <p className="text-xs text-gray-600 mt-1">{new Date(t.at).toLocaleTimeString('fr-FR')}</p>
          </div>

          <button
            onClick={() => onDismiss(t.id)}
            className="flex-shrink-0 text-gray-600 hover:text-gray-300 transition-colors mt-0.5"
          >
            <X size={14} />
          </button>

          {/* auto-shrink progress bar */}
          <div
            className="absolute bottom-0 left-0 h-0.5 bg-red-500/50 rounded-full"
            style={{ animation: `shrink ${t.ttl}ms linear forwards` }}
          />
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const [view, setView] = useState(() => {
    try {
      const saved = window.localStorage.getItem('guardian.dashboard.view');
      if (saved === 'list' || saved === 'sla' || saved === 'stats' || saved === 'network' || saved === 'agent-reports') {
        return saved;
      }
    } catch (_) {
      // Ignore storage access issues and fallback to default view.
    }
    return 'list';
  });
  const [selectedId, setSelectedId] = useState(null);
  const [refreshSignal, setRefreshSignal] = useState(0);
  const [toasts, setToasts] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [agentUnreadCount, setAgentUnreadCount] = useState(0);
  const [latestDetectedIp, setLatestDetectedIp] = useState(null);
  const recentDeviceAlertRef = useRef(new Map());

  useEffect(() => {
    try {
      window.localStorage.setItem('guardian.dashboard.view', view);
    } catch (_) {
      // Ignore persistence errors and keep runtime behavior.
    }
  }, [view]);

  // ── Dismiss a toast by id ────────────────────────────────────────────────
  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // ── Push a new danger toast ──────────────────────────────────────────────
  const pushToast = useCallback((title, body) => {
    const id = Date.now() + Math.random();
    const ttl = 8000; // ms before auto-dismiss
    setToasts((prev) => [{ id, title, body, at: new Date().toISOString(), ttl }, ...prev].slice(0, 6));
    setTimeout(() => dismissToast(id), ttl);
  }, [dismissToast]);

  // ── Global socket listener — active on ALL tabs ──────────────────────────
  useEffect(() => {
    const s = connectSocket();

    s.on('scanner:device_detected', ({ ip, openPort, osHint, detectedAt }) => {
      const nowMs = Date.now();
      const lastSeen = recentDeviceAlertRef.current.get(ip) || 0;
      // Skip duplicate notifications for the same IP in a short burst window.
      if (nowMs - lastSeen < 4000) {
        return;
      }
      recentDeviceAlertRef.current.set(ip, nowMs);

      const os = osHint === 'linux' ? '🐧 Linux' : osHint === 'windows' ? '🪟 Windows' : osHint === 'server' ? '🌐 Serveur' : 'OS inconnu';
      const title = `🚨 Appareil inconnu — ${ip}`;
      const body = `Port ${openPort || '?'} · ${os} · Incident créé automatiquement`;

      setUnreadCount((c) => Math.min(99, c + 1));
      setLatestDetectedIp(ip);
      pushToast(
        title,
        body
      );
      setRefreshSignal((s) => s + 1); // refresh incident list
    });

    s.on('incident:new', ({ category, severity, source, ip_address }) => {
      if (source === 'SYSTEM_SCANNER') return; // already shown above
      pushToast(
        `Nouvel incident ${severity?.toUpperCase() || ''}`,
        `Catégorie : ${category || 'other'} · Source : ${source || 'USER'}${ip_address ? ` · IP : ${ip_address}` : ''}`
      );
      setRefreshSignal((s) => s + 1);
    });

    s.on('cyberagent:report', ({ classification, risk_score, event_type, source_ip }) => {
      setAgentUnreadCount((c) => Math.min(99, c + 1));
      pushToast(
        `Cyber-agent ${classification || 'ALERTE'} · ${risk_score ?? '?'}%`,
        `${event_type || 'evenement'}${source_ip ? ` · Source ${source_ip}` : ''}`
      );
    });

    return () => {
      s.off('scanner:device_detected');
      s.off('incident:new');
      s.off('cyberagent:report');
    };
  }, [pushToast]);

  // ── Clear unread count when user opens network tab ───────────────────────
  const goToNetwork = () => {
    setView('network');
    setSelectedId(null);
    setUnreadCount(0);
    setLatestDetectedIp(null);
  };

  const goToAgentReports = () => {
    setView('agent-reports');
    setSelectedId(null);
    setAgentUnreadCount(0);
  };

  const handleSelect = (incident) => setSelectedId(incident.id);
  const handleClose  = () => setSelectedId(null);
  const handleStatusChange = () => setRefreshSignal((s) => s + 1);

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      {/* Global toasts — visible on ANY tab */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      {/* Top Nav */}
      <header className="border-b border-gray-800 bg-gray-900/60 backdrop-blur sticky top-0 z-20">
        <div className="max-w-screen-2xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield size={20} className="text-blue-400" />
            <span className="text-gray-100 font-bold text-lg tracking-tight">Guardian</span>
            <span className="text-gray-500 text-sm">SOC Dashboard</span>
          </div>

          <nav className="flex items-center gap-1">
            <button
              onClick={goToNetwork}
              title={latestDetectedIp ? `Nouvelle IP: ${latestDetectedIp}` : 'Notifications réseau'}
              className={`relative flex items-center justify-center w-9 h-9 rounded-lg transition-colors ${
                unreadCount > 0
                  ? 'text-red-300 bg-red-500/10 hover:bg-red-500/20'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`}
            >
              <Bell size={15} className={unreadCount > 0 ? 'animate-pulse' : ''} />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 min-w-[16px] h-4 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center px-1">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>
            {latestDetectedIp && unreadCount > 0 && (
              <span className="hidden md:inline-flex text-[11px] font-mono text-red-300 bg-red-500/10 border border-red-500/20 rounded-md px-2 py-1">
                {latestDetectedIp}
              </span>
            )}
            <button
              onClick={() => setView('list')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-colors ${
                view === 'list' ? 'bg-gray-700 text-gray-100' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`}
            >
              <List size={14} />
              Incidents
            </button>
            <button
              onClick={() => setView('sla')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-colors ${
                view === 'sla' ? 'bg-gray-700 text-gray-100' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`}
            >
              <Siren size={14} />
              SLA
            </button>
            <button
              onClick={() => { setView('stats'); setSelectedId(null); }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-colors ${
                view === 'stats' ? 'bg-gray-700 text-gray-100' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`}
            >
              <BarChart2 size={14} />
              Statistiques
            </button>
            <button
              onClick={goToNetwork}
              className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-colors ${
                view === 'network' ? 'bg-gray-700 text-gray-100' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`}
            >
              <Wifi size={14} />
              Réseau
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 min-w-[16px] h-4 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center px-1 animate-pulse">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>
            <button
              onClick={goToAgentReports}
              className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-colors ${
                view === 'agent-reports' ? 'bg-gray-700 text-gray-100' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`}
            >
              <Bot size={14} />
              Agent Reports
              {agentUnreadCount > 0 && (
                <span className="absolute -top-1 -right-1 min-w-[16px] h-4 bg-cyan-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center px-1 animate-pulse">
                  {agentUnreadCount > 9 ? '9+' : agentUnreadCount}
                </span>
              )}
            </button>
          </nav>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 max-w-screen-2xl mx-auto w-full px-6 py-6">
        {view === 'stats' ? (
          <StatsView />
        ) : view === 'agent-reports' ? (
          <AgentReportsView />
        ) : view === 'network' ? (
          <NetworkScanView />
        ) : (
          <div className="flex gap-6 h-[calc(100vh-8rem)]">
            {/* Left: incident list */}
            <div className={`${selectedId ? 'w-[420px] shrink-0' : 'flex-1'} card overflow-hidden flex flex-col transition-all`}>
              {view === 'sla' ? (
                <SlaBoard
                  onSelect={handleSelect}
                  refreshSignal={refreshSignal}
                />
              ) : (
                <IncidentList
                  onSelect={handleSelect}
                  selectedId={selectedId}
                  refreshSignal={refreshSignal}
                />
              )}
            </div>

            {/* Right: detail panel */}
            {selectedId && (
              <div className="flex-1 card overflow-hidden flex flex-col min-w-0">
                <IncidentDetail
                  incidentId={selectedId}
                  onClose={handleClose}
                  onStatusChange={handleStatusChange}
                />
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
