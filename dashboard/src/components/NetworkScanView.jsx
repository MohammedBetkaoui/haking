import React, { useEffect, useRef, useState, useCallback } from 'react';
import { connectSocket } from '../lib/socket';
import { fetchNetworkHosts } from '../lib/api';
import DeviceDetailsModal from './DeviceDetailsModal';
import {
  Wifi, WifiOff, ShieldAlert, CheckCircle2, Clock,
  Loader2, Radio, AlertTriangle, ScanLine, Search,
} from 'lucide-react';

// ─── Constants ───────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  // New statuses
  new_external:         { label: 'Nouveau inconnu',    bg: 'bg-red-500/10',    border: 'border-red-500/30',    text: 'text-red-300',    dot: 'bg-red-500'    },
  external_seen_before: { label: 'Inconnu récurrent', bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-300', dot: 'bg-orange-500' },
  known:                { label: 'Baseline réseau',  bg: 'bg-green-500/5',   border: 'border-green-500/20',  text: 'text-green-300',  dot: 'bg-green-500'  },
  local_trusted:        { label: 'De confiance',       bg: 'bg-gray-800/50',   border: 'border-gray-700/40',   text: 'text-gray-500',   dot: 'bg-gray-600'   },
  // Backward compat with old statuses in persisted registry
  new:     { label: 'Inconnu',    bg: 'bg-red-500/10',  border: 'border-red-500/30',  text: 'text-red-300',  dot: 'bg-red-500'  },
  trusted: { label: 'De confiance', bg: 'bg-gray-800/50', border: 'border-gray-700/40', text: 'text-gray-500', dot: 'bg-gray-600' },
};

// ─── Main Component ───────────────────────────────────────────────────────────

export default function NetworkScanView() {
  const [initialized, setInitialized]   = useState(false);
  const [scanning, setScanning]         = useState(false);
  const [scanProgress, setScanProgress] = useState({ found: 0, total: 0 });
  const [lastScan, setLastScan]         = useState(null);
  const [hosts, setHosts]               = useState([]);     // Map-like: ip → entry
  const [alerts, setAlerts]             = useState([]);     // unknown devices this session
  const [filter, setFilter]             = useState('all'); // all | new | known | trusted
  const [search, setSearch]             = useState('');
  const [newFlash, setNewFlash]         = useState(null);   // ip currently flashing red
  const [selectedIp, setSelectedIp]     = useState(null);   // ip opened in DeviceDetailsModal
  const alertsRef                       = useRef(null);

  // ── Load existing hosts on mount (HTTP) ─────────────────────────────────────
  useEffect(() => {
    fetchNetworkHosts()
      .then(({ initialized: init, hosts: h }) => {
        if (h?.length) {
          setHosts(h);
          setInitialized(init);
        }
      })
      .catch(() => {}); // scanner may not be enabled — silent
  }, []);

  // ── Socket.io real-time updates ─────────────────────────────────────────────
  useEffect(() => {
    const s = connectSocket();

    // Scan begins
    s.on('scanner:scan_start', ({ totalHosts, subnets, probePort, startedAt }) => {
      setScanning(true);
      setScanProgress({ found: 0, total: totalHosts });
      setLastScan((prev) => ({ ...prev, subnets, probePort, startedAt }));
    });

    // Each alive host discovered — add/update in list live
    s.on('scanner:host_found', (entry) => {
      setScanProgress((p) => ({ ...p, found: p.found + 1 }));
      setHosts((prev) => {
        const idx = prev.findIndex((h) => h.ip === entry.ip);
        if (idx >= 0) {
          const updated = [...prev];
          updated[idx] = entry;
          return updated;
        }
        return [entry, ...prev];
      });
    });

    // Baseline complete
    s.on('scanner:baseline', ({ hosts: h, subnets, probePorts, probePort, scannedAt, durationMs }) => {
      const ports = probePorts || (probePort ? [probePort] : []);
      setHosts(h);
      setScanning(false);
      setInitialized(true);
      setLastScan({ subnets, probePorts: ports, scannedAt, durationMs });
      setScanProgress({ found: h.length, total: h.length });
    });

    // Subsequent scan complete
    s.on('scanner:scan_complete', ({ hosts: h, knownCount, newCount, subnets, probePorts, probePort, scannedAt, durationMs }) => {
      const ports = probePorts || (probePort ? [probePort] : []);
      setHosts(h);
      setScanning(false);
      setLastScan({ subnets, probePorts: ports, scannedAt, durationMs, knownCount, newCount });
      setScanProgress({ found: h.length, total: h.length });
    });

    // Unknown device — alert panel + red flash
    s.on('scanner:device_detected', ({ ip, detectedAt }) => {
      setAlerts((prev) => [{ ip, detectedAt }, ...prev].slice(0, 100));
      setNewFlash(ip);
      setTimeout(() => setNewFlash(null), 3000);
      setTimeout(() => alertsRef.current?.scrollIntoView({ behavior: 'smooth' }), 150);
    });

    return () => {
      s.off('scanner:scan_start');
      s.off('scanner:host_found');
      s.off('scanner:baseline');
      s.off('scanner:scan_complete');
      s.off('scanner:device_detected');
    };
  }, []);

  // ── Derived data ─────────────────────────────────────────────────────────────
  const isUnknown    = (h) => h.status === 'new_external' || h.status === 'external_seen_before' || h.status === 'new';
  const isKnown      = (h) => h.status === 'known';
  const isTrustedDev = (h) => h.status === 'local_trusted' || h.status === 'trusted';

  const knownCount   = hosts.filter(isKnown).length;
  const unknownCount = hosts.filter(isUnknown).length;
  const trustedCount = hosts.filter(isTrustedDev).length;

  const filteredHosts = hosts.filter((h) => {
    const matchFilter =
      filter === 'all'     ||
      (filter === 'unknown'  && isUnknown(h))  ||
      (filter === 'known'    && isKnown(h))    ||
      (filter === 'trusted'  && isTrustedDev(h));
    const matchSearch = !search || h.ip.includes(search.trim());
    return matchFilter && matchSearch;
  });

  const progressPct = scanProgress.total > 0
    ? Math.round((scanProgress.found / scanProgress.total) * 100)
    : 0;

  return (
    <div className="flex flex-col gap-5 w-full pb-8">

      {/* ── Device Details Modal ──────────────────────────── */}
      {selectedIp && (
        <DeviceDetailsModal
          ip={selectedIp}
          onClose={() => setSelectedIp(null)}
        />
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard icon={<Wifi size={16} className="text-blue-400" />}      label="Appareils actifs"  value={hosts.length}   color="blue" glow={scanning} />
        <StatCard icon={<CheckCircle2 size={16} className="text-green-400" />} label="Connus"        value={knownCount}     color="green" />
        <StatCard icon={<ShieldAlert size={16} className="text-red-400" />} label="Inconnus"         value={unknownCount}   color="red"  glow={unknownCount > 0} />
        <StatCard icon={<Clock size={16} className="text-gray-400" />}     label="Dernier scan"      value={lastScan ? formatRelative(lastScan.scannedAt) : '—'} sub={lastScan?.durationMs ? `${lastScan.durationMs} ms` : null} color="gray" />
      </div>

      {/* ── Scanner info bar + progress ─────────────────── */}
      <div className="card px-4 py-3 flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-4 text-sm text-gray-400">
          <span className="flex items-center gap-1.5">
            <Radio size={13} className="text-blue-400" />
            Subnet : <span className="text-gray-200 ml-1">{lastScan?.subnets?.join(', ') || '—'}</span>
          </span>
          <span>Ports : <span className="text-gray-200">{lastScan?.probePorts?.join(', ') || '—'}</span></span>
          {lastScan?.scannedAt && (
            <span>Scan : <span className="text-gray-200">{new Date(lastScan.scannedAt).toLocaleTimeString('fr-FR')}</span></span>
          )}
          <span className="ml-auto flex items-center gap-1.5">
            {scanning
              ? <><Loader2 size={12} className="animate-spin text-blue-400" /><span className="text-blue-400 text-xs">Scan en cours…</span></>
              : initialized
                ? <><ScanLine size={12} className="text-green-500" /><span className="text-green-500 text-xs">Prêt</span></>
                : <span className="text-gray-600 text-xs">En attente du scanner</span>
            }
          </span>
        </div>

        {/* Progress bar */}
        {scanning && (
          <div className="flex items-center gap-3">
            <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 rounded-full transition-all duration-300"
                style={{ width: `${progressPct}%` }}
              />
            </div>
            <span className="text-xs text-gray-500 tabular-nums shrink-0">
              {scanProgress.found} / {scanProgress.total} IP
            </span>
          </div>
        )}
      </div>

      {/* ── Waiting state ───────────────────────────────── */}
      {!initialized && !scanning && (
        <div className="card flex flex-col items-center justify-center py-20 gap-4 text-gray-500">
          <Loader2 size={32} className="animate-spin text-blue-500" />
          <p className="text-sm">En attente du premier scan réseau…</p>
          <p className="text-xs text-gray-600">Assurez-vous que <code className="text-gray-500">AUTO_DETECT_SCANNER_ENABLED=true</code> dans le .env</p>
        </div>
      )}

      {/* ── Alert banner: unknown devices ──────────────── */}
      {alerts.length > 0 && (
        <div ref={alertsRef} className="card border border-red-500/20 overflow-hidden">
          <div className="px-4 py-3 border-b border-red-500/20 bg-red-500/5 flex items-center gap-2">
            <AlertTriangle size={15} className="text-red-400 animate-pulse" />
            <span className="text-sm font-semibold text-red-400">Appareils inconnus détectés cette session</span>
            <span className="ml-auto text-xs text-red-500/70">{alerts.length} alerte{alerts.length > 1 ? 's' : ''}</span>
          </div>
          <ul className="divide-y divide-gray-800/60 max-h-48 overflow-y-auto">
            {alerts.map((a, i) => (
              <li key={`${a.ip}-${i}`} className="flex items-center gap-3 px-4 py-2.5">
                <span className="w-2 h-2 rounded-full bg-red-500 shrink-0 animate-pulse" />
                <span className="font-mono text-sm text-red-300 tracking-wide">{a.ip}</span>
                <span className="ml-auto text-xs text-gray-500">
                  {new Date(a.detectedAt).toLocaleTimeString('fr-FR')}
                </span>
                <span className="badge-critical shrink-0">Incident créé</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ── IP Table ────────────────────────────────────── */}
      {(initialized || hosts.length > 0) && (
        <div className="card overflow-hidden">
          {/* Table header */}
          <div className="px-4 py-3 border-b border-gray-800 flex flex-wrap items-center gap-3">
            {/* Filter tabs */}
            <div className="flex items-center gap-1">
              {[
                { key: 'all',     label: `Tous (${hosts.length})` },
                { key: 'unknown', label: `Inconnus (${unknownCount})` },
                { key: 'known',   label: `Baseline (${knownCount})` },
                { key: 'trusted', label: `Confiance (${trustedCount})` },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  onClick={() => setFilter(key)}
                  className={`text-xs px-3 py-1 rounded-lg transition-colors ${
                    filter === key
                      ? 'bg-gray-700 text-gray-100'
                      : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            {/* Search */}
            <div className="ml-auto flex items-center gap-2 bg-gray-800/60 border border-gray-700/50 rounded-lg px-3 py-1.5">
              <Search size={12} className="text-gray-500" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filtrer par IP…"
                className="bg-transparent text-xs text-gray-300 placeholder-gray-600 outline-none w-32"
              />
            </div>
          </div>

          {/* Table */}
          {filteredHosts.length === 0 ? (
            <div className="py-12 text-center text-gray-600 text-sm">
              {scanning ? 'Scan en cours…' : 'Aucun hôte trouvé'}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wide">
                    <th className="text-left px-4 py-2.5 font-medium">Adresse IP</th>
                    <th className="text-left px-4 py-2.5 font-medium">Statut</th>
                    <th className="text-left px-4 py-2.5 font-medium hidden sm:table-cell">Port sondé</th>
                    <th className="text-left px-4 py-2.5 font-medium hidden md:table-cell">Première détection</th>
                    <th className="text-left px-4 py-2.5 font-medium hidden md:table-cell">Dernière vue</th>
                    <th className="text-right px-4 py-2.5 font-medium hidden lg:table-cell">Scans</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {filteredHosts.map((host) => (
                    <HostRow
                      key={host.ip}
                      host={host}
                      flash={newFlash === host.ip}
                      onIpClick={setSelectedIp}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── HostRow ───────────────────────────────────────────────────────────────────

/** Returns true for any status that means "unknown / suspicious device" */
function isUnknownStatus(status) {
  return status === 'new_external' || status === 'external_seen_before' || status === 'new';
}

function HostRow({ host, flash, onIpClick }) {
  const cfg = STATUS_CONFIG[host.status] || STATUS_CONFIG.known;

  return (
    <tr
      className={`transition-colors duration-500 ${
        flash
          ? 'bg-red-500/20'
          : isUnknownStatus(host.status)
            ? 'bg-red-500/5 hover:bg-red-500/10'
            : 'hover:bg-gray-800/30'
      }`}
    >
      {/* IP */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2.5">
          <span className={`w-2 h-2 rounded-full shrink-0 ${cfg.dot} ${isUnknownStatus(host.status) ? 'animate-pulse' : ''}`} />
          <button
            onClick={() => onIpClick(host.ip)}
            className={`font-mono font-semibold tracking-wide underline-offset-2 hover:underline focus:outline-none
              ${isUnknownStatus(host.status) ? 'text-red-300 hover:text-red-200' : 'text-gray-200 hover:text-blue-300'}`}
            title={`View details for ${host.ip}`}
          >
            {host.ip}
          </button>
          {flash && (
            <span className="ml-1 badge-critical text-xs animate-pulse">NOUVEAU</span>
          )}
        </div>
      </td>

      {/* Status badge */}
      <td className="px-4 py-3">
        <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-0.5 rounded-full border ${cfg.bg} ${cfg.border} ${cfg.text} font-medium`}>
          {isUnknownStatus(host.status)                                     && <ShieldAlert size={11} />}
          {host.status === 'known'                                          && <CheckCircle2 size={11} />}
          {(host.status === 'local_trusted' || host.status === 'trusted')   && <WifiOff size={11} />}
          {cfg.label}
        </span>
      </td>

      {/* Port / OS */}
      <td className="px-4 py-3 hidden sm:table-cell">
        {host.openPort ? (
          <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-mono font-medium border ${
            host.osHint === 'linux'   ? 'bg-orange-500/10 border-orange-500/30 text-orange-300' :
            host.osHint === 'windows' ? 'bg-blue-500/10   border-blue-500/30   text-blue-300'   :
            host.osHint === 'server'  ? 'bg-purple-500/10 border-purple-500/30 text-purple-300' :
                                        'bg-gray-700/30   border-gray-600      text-gray-400'
          }`}>
            :{host.openPort}
            {host.osHint === 'linux'   && ' 🐧'}
            {host.osHint === 'windows' && ' 🪟'}
            {host.osHint === 'server'  && ' 🌐'}
          </span>
        ) : (
          <span className="text-xs text-gray-600">—</span>
        )}
      </td>

      {/* First seen */}
      <td className="px-4 py-3 hidden md:table-cell">
        <span className="text-xs text-gray-500">
          {host.firstSeen ? new Date(host.firstSeen).toLocaleString('fr-FR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' }) : '—'}
        </span>
      </td>

      {/* Last seen */}
      <td className="px-4 py-3 hidden md:table-cell">
        <span className="text-xs text-gray-400">
          {host.lastSeen ? formatRelative(host.lastSeen) : '—'}
        </span>
      </td>

      {/* Scan count */}
      <td className="px-4 py-3 hidden lg:table-cell text-right">
        <span className="text-xs text-gray-600 tabular-nums">{host.scanCount ?? '—'}</span>
      </td>
    </tr>
  );
}

// ── StatCard ──────────────────────────────────────────────────────────────────

function StatCard({ icon, label, value, sub, color, glow }) {
  const colors = {
    blue:  'border-blue-500/20  bg-blue-500/5',
    green: 'border-green-500/20 bg-green-500/5',
    red:   'border-red-500/20   bg-red-500/5',
    gray:  'border-gray-700/40  bg-gray-800/30',
  };
  return (
    <div className={`card px-4 py-3 flex flex-col gap-1 border ${colors[color] || colors.gray} ${glow ? 'ring-1 ring-current ring-opacity-30' : ''} transition-all duration-300`}>
      <div className="flex items-center gap-2 text-xs text-gray-500">{icon}{label}</div>
      <div className="text-2xl font-bold text-gray-100 tabular-nums">{value}</div>
      {sub && <div className="text-xs text-gray-600">{sub}</div>}
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatRelative(isoString) {
  if (!isoString) return '—';
  const diff = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (diff < 5)    return 'à l\'instant';
  if (diff < 60)   return `il y a ${diff}s`;
  if (diff < 3600) return `il y a ${Math.floor(diff / 60)}min`;
  return new Date(isoString).toLocaleTimeString('fr-FR');
}
