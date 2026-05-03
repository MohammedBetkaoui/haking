import React, { useState, useEffect, useCallback, useRef } from 'react';
import IncidentList from './components/IncidentList';
import IncidentDetail from './components/IncidentDetail';
import SlaBoard from './components/SlaBoard';
import StatsView from './components/StatsView';
import NetworkScanView from './components/NetworkScanView';
import AgentReportsView from './components/AgentReportsView';
import { connectSocket } from './lib/socket';
import { getPortCheckReportDownloadUrl } from './lib/api';
import { Shield, BarChart2, List, Siren, Wifi, ShieldAlert, X, Bell, Bot } from 'lucide-react';

// ─── Browser Notification helpers ────────────────────────────────────────────

function requestBrowserNotificationPermission() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'default') {
    Notification.requestPermission().catch(() => {});
  }
}

function sendBrowserNotification(title, body, tag) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  try {
    new Notification(title, { body, tag, icon: '/favicon.ico', requireInteraction: true });
  } catch (_) {}
}

// ─── Auto-download report as CSV ─────────────────────────────────────────────

function downloadPortCheckReport() {
  try {
    const url = getPortCheckReportDownloadUrl();
    const a = document.createElement('a');
    a.href = url;
    a.download = `open-port-report-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } catch (_) {}
}

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
  const [portThreatCount, setPortThreatCount] = useState(0);
  const recentDeviceAlertRef = useRef(new Map());

  // ── Request browser notification permission on first render ─────────────
  useEffect(() => {
    requestBrowserNotificationPermission();
  }, []);

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
      pushToast(title, body);
      sendBrowserNotification(title, body, `device-${ip}`);
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

    // ── Port-intrusion: fire browser notification + auto-download report ────
    s.on('scan:port-check:done', (payload) => {
      if (!payload) return;
      const abnormal = payload.abnormal || [];
      const open     = payload.open     || [];
      if (abnormal.length === 0 && open.length === 0) return;

      const targetIp = payload.target_ip || 'local';
      const title    = `🔓 Ports suspects détectés — ${targetIp}`;
      const body     = abnormal.length > 0
        ? `Ports non autorisés : ${abnormal.join(', ')} · Rapport téléchargé automatiquement`
        : `${open.length} port(s) ouvert(s) détectés sur ${targetIp}`;

      setPortThreatCount((c) => Math.min(99, c + 1));
      pushToast(title, body);
      sendBrowserNotification(title, body, `port-check-${targetIp}`);

      // Auto-save the report as CSV
      if (abnormal.length > 0) {
        downloadPortCheckReport();
      }

      setRefreshSignal((prev) => prev + 1);
    });

    return () => {
      s.off('scanner:device_detected');
      s.off('incident:new');
      s.off('cyberagent:report');
      s.off('scan:port-check:done');
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

  // ── Keyboard shortcuts (1-5 to switch views) ────────────────────────────
  useEffect(() => {
    const handler = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
      if (e.key === '1') { setView('list'); setSelectedId(null); }
      else if (e.key === '2') { setView('sla'); setSelectedId(null); }
      else if (e.key === '3') { setView('stats'); setSelectedId(null); }
      else if (e.key === '4') { goToNetwork(); }
      else if (e.key === '5') { goToAgentReports(); }
      else if (e.key === 'Escape') { setSelectedId(null); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps

  const navBtn = (active, onClick, children, extra = '') => (
    <button
      onClick={onClick}
      className={`nav-btn relative flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg transition-all duration-150 ${
        active
          ? 'text-blue-300 bg-blue-500/10 nav-active'
          : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800/70'
      } ${extra}`}
    >
      {children}
    </button>
  );

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      {/* Global toasts — visible on ANY tab */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Top Nav */}
      <header className="border-b border-gray-800/80 bg-gray-900/80 backdrop-blur-md sticky top-0 z-20">
        {/* critical alert ribbon */}
        {portThreatCount > 0 && (
          <div className="bg-red-900/40 border-b border-red-800/50 px-4 py-1.5 flex items-center justify-between">
            <span className="text-red-300 text-xs font-medium flex items-center gap-2">
              <ShieldAlert size={13} className="animate-pulse" />
              {portThreatCount} alerte(s) port — rapport téléchargé automatiquement
            </span>
            <button onClick={() => setPortThreatCount(0)} className="text-red-400/60 hover:text-red-300 ml-4">
              <X size={13} />
            </button>
          </div>
        )}

        <div className="max-w-screen-2xl mx-auto px-6 h-14 flex items-center justify-between gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2.5 shrink-0">
            <div className="w-8 h-8 rounded-xl bg-blue-500/15 border border-blue-500/25 flex items-center justify-center">
              <Shield size={16} className="text-blue-400" />
            </div>
            <div className="leading-none">
              <span className="text-gray-100 font-bold text-base tracking-tight">Guardian</span>
              <span className="hidden sm:inline text-gray-500 text-xs ml-2">SOC Dashboard</span>
            </div>
          </div>

          {/* Nav */}
          <nav className="flex items-center gap-0.5">
            {/* Bell notification icon */}
            <button
              onClick={goToNetwork}
              title={latestDetectedIp ? `Nouvelle IP: ${latestDetectedIp}` : 'Notifications réseau'}
              className={`relative flex items-center justify-center w-9 h-9 rounded-lg mr-1 transition-all duration-150 ${
                unreadCount > 0
                  ? 'text-red-300 bg-red-500/10 hover:bg-red-500/20'
                  : 'text-gray-500 hover:text-gray-200 hover:bg-gray-800/70'
              }`}
            >
              <Bell size={15} className={unreadCount > 0 ? 'animate-pulse' : ''} />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 min-w-[16px] h-4 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center px-1 shadow-lg shadow-red-900/50">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>
            {latestDetectedIp && unreadCount > 0 && (
              <span className="hidden lg:inline-flex text-[11px] font-mono text-red-300 bg-red-500/10 border border-red-500/20 rounded-md px-2 py-1 mr-2">
                {latestDetectedIp}
              </span>
            )}

            {/* Divider */}
            <div className="w-px h-5 bg-gray-800 mx-1 hidden sm:block" />

            {navBtn(view === 'list', () => { setView('list'); setSelectedId(null); },
              <><List size={13} /><span>Incidents</span><span className="hidden lg:inline text-[10px] text-gray-600 ml-0.5">1</span></>
            )}
            {navBtn(view === 'sla', () => { setView('sla'); setSelectedId(null); },
              <><Siren size={13} /><span>SLA</span><span className="hidden lg:inline text-[10px] text-gray-600 ml-0.5">2</span></>
            )}
            {navBtn(view === 'stats', () => { setView('stats'); setSelectedId(null); },
              <><BarChart2 size={13} /><span className="hidden sm:inline">Statistiques</span><span className="hidden lg:inline text-[10px] text-gray-600 ml-0.5">3</span></>
            )}
            {navBtn(view === 'network', goToNetwork,
              <>
                <Wifi size={13} />
                <span className="hidden sm:inline">Réseau</span>
                <span className="hidden lg:inline text-[10px] text-gray-600 ml-0.5">4</span>
                {unreadCount > 0 && (
                  <span className="absolute -top-1 -right-1 min-w-[16px] h-4 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center px-1 animate-pulse shadow-lg shadow-red-900/50">
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </span>
                )}
              </>
            )}
            {navBtn(view === 'agent-reports', goToAgentReports,
              <>
                <Bot size={13} />
                <span className="hidden sm:inline">Agent</span>
                <span className="hidden lg:inline text-[10px] text-gray-600 ml-0.5">5</span>
                {agentUnreadCount > 0 && (
                  <span className="absolute -top-1 -right-1 min-w-[16px] h-4 bg-cyan-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center px-1 animate-pulse shadow-lg shadow-cyan-900/50">
                    {agentUnreadCount > 9 ? '9+' : agentUnreadCount}
                  </span>
                )}
              </>
            )}
          </nav>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 max-w-screen-2xl mx-auto w-full px-4 md:px-6 py-5 animate-fade-up">
        {view === 'stats' ? (
          <StatsView />
        ) : view === 'agent-reports' ? (
          <AgentReportsView />
        ) : view === 'network' ? (
          <NetworkScanView />
        ) : (
          <div className="flex gap-5 h-[calc(100vh-7.5rem)]">
            {/* Left: incident list */}
            <div className={`${selectedId ? 'w-[440px] shrink-0' : 'flex-1'} card overflow-hidden flex flex-col transition-all duration-200`}>
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
