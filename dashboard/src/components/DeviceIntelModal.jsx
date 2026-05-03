import React, { useEffect, useState, useCallback } from 'react';
import {
  X, Shield, ShieldCheck, ShieldAlert, Monitor, Smartphone,
  Wifi, Cpu, Server, Globe, Clock, Hash, Activity,
  AlertTriangle, CheckCircle2, XCircle, Loader2, RefreshCw,
  BarChart2, MapPin, ChevronRight, ExternalLink, Zap,
  Printer, Database, Info,
} from 'lucide-react';
import { fetchMacIntel } from '../lib/api';

// ─── Device type config ───────────────────────────────────────────────────────

const DEVICE_TYPE_CONFIG = {
  'Desktop':    { icon: Monitor,    color: 'text-blue-400',    bg: 'bg-blue-500/15',    border: 'border-blue-500/25'    },
  'Laptop':     { icon: Monitor,    color: 'text-cyan-400',    bg: 'bg-cyan-500/15',    border: 'border-cyan-500/25'    },
  'Smartphone': { icon: Smartphone, color: 'text-green-400',   bg: 'bg-green-500/15',   border: 'border-green-500/25'   },
  'Tablet':     { icon: Monitor,    color: 'text-teal-400',    bg: 'bg-teal-500/15',    border: 'border-teal-500/25'    },
  'Router':     { icon: Wifi,       color: 'text-purple-400',  bg: 'bg-purple-500/15',  border: 'border-purple-500/25'  },
  'Printer':    { icon: Printer,    color: 'text-orange-400',  bg: 'bg-orange-500/15',  border: 'border-orange-500/25'  },
  'IoT Device': { icon: Cpu,        color: 'text-yellow-400',  bg: 'bg-yellow-500/15',  border: 'border-yellow-500/25'  },
  'Unknown':    { icon: Server,     color: 'text-gray-400',    bg: 'bg-gray-700/40',    border: 'border-gray-600/40'    },
};

// ─── Trust config ─────────────────────────────────────────────────────────────

const TRUST_CONFIG = {
  trusted: {
    label: 'Trusted',      icon: ShieldCheck,
    bg: 'bg-green-500/12',    border: 'border-green-500/40',
    text: 'text-green-400',   dot: 'bg-green-500',
    glow: 'shadow-green-500/10',
    bannerBg: 'bg-green-500/8',  bannerBorder: 'border-green-500/25',  bannerText: 'text-green-300',
  },
  unknown: {
    label: 'Unknown',      icon: Shield,
    bg: 'bg-yellow-500/12',   border: 'border-yellow-500/40',
    text: 'text-yellow-400',  dot: 'bg-yellow-500',
    glow: 'shadow-yellow-500/10',
    bannerBg: 'bg-yellow-500/8', bannerBorder: 'border-yellow-500/25', bannerText: 'text-yellow-300',
  },
  suspicious: {
    label: 'Suspicious',   icon: ShieldAlert,
    bg: 'bg-red-500/12',      border: 'border-red-500/40',
    text: 'text-red-400',     dot: 'bg-red-500',
    glow: 'shadow-red-500/10',
    bannerBg: 'bg-red-500/8',    bannerBorder: 'border-red-500/25',    bannerText: 'text-red-300',
  },
  blocked: {
    label: 'Blocked',      icon: ShieldAlert,
    bg: 'bg-red-900/30',      border: 'border-red-700/60',
    text: 'text-red-500',     dot: 'bg-red-700',
    glow: 'shadow-red-500/10',
    bannerBg: 'bg-red-900/20',   bannerBorder: 'border-red-700/40',    bannerText: 'text-red-400',
  },
};

// ─── Alert level config ───────────────────────────────────────────────────────

const ALERT_LEVEL_CONFIG = {
  low:      { label: 'LOW',      bar: 'bg-green-500',  text: 'text-green-400',  track: 'bg-green-500/20'  },
  medium:   { label: 'MEDIUM',   bar: 'bg-yellow-500', text: 'text-yellow-400', track: 'bg-yellow-500/20' },
  high:     { label: 'HIGH',     bar: 'bg-orange-500', text: 'text-orange-400', track: 'bg-orange-500/20' },
  critical: { label: 'CRITICAL', bar: 'bg-red-500',    text: 'text-red-400',    track: 'bg-red-500/20'    },
};

const CONFIDENCE_CONFIG = {
  high:    { label: 'High',    className: 'bg-green-500/15 border-green-500/30 text-green-400'   },
  medium:  { label: 'Medium',  className: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-400' },
  low:     { label: 'Low',     className: 'bg-red-500/15 border-red-500/30 text-red-400'          },
  unknown: { label: 'Unknown', className: 'bg-gray-700/40 border-gray-600/40 text-gray-500'       },
};

// ─── Component ────────────────────────────────────────────────────────────────

/**
 * DeviceIntelModal
 *
 * Props:
 *   mac          — MAC address string (AA:BB:CC:DD:EE:FF)
 *   ip           — optional IP hint for registry cross-reference
 *   onClose      — callback to close this modal
 *   onViewDevice — optional: called with (ip) to open DeviceDetailsModal for the current IP
 */
export default function DeviceIntelModal({ mac, ip, onClose, onViewDevice }) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchMacIntel(mac, ip || null);
      setData(result);
    } catch (err) {
      setError(err?.response?.data?.error || 'Failed to load MAC intelligence.');
    } finally {
      setLoading(false);
    }
  }, [mac, ip]);

  useEffect(() => { load(); }, [load]);

  // Escape key
  useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [onClose]);

  // ── Derived values ────────────────────────────────────────────────────────
  const trustKey   = (data?.trustStatus && TRUST_CONFIG[data.trustStatus]) ? data.trustStatus : 'unknown';
  const trustCfg   = TRUST_CONFIG[trustKey];
  const TrustIcon  = trustCfg.icon;

  const typeKey    = data?.deviceType || 'Unknown';
  const typeCfg    = DEVICE_TYPE_CONFIG[typeKey] || DEVICE_TYPE_CONFIG['Unknown'];
  const TypeIcon   = typeCfg.icon;

  const alertKey   = data?.alertLevel || 'low';
  const alertCfg   = ALERT_LEVEL_CONFIG[alertKey] || ALERT_LEVEL_CONFIG.low;

  const confKey    = data?.vendorConfidence || 'unknown';
  const confCfg    = CONFIDENCE_CONFIG[confKey] || CONFIDENCE_CONFIG.unknown;

  return (
    <div
      className="fixed inset-0 z-60 flex items-center justify-center bg-black/80 backdrop-blur-sm"
      style={{ animation: 'dim-fade 150ms ease-out both' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className={`
          relative w-full max-w-2xl mx-4 bg-gray-900
          border rounded-2xl shadow-2xl overflow-hidden flex flex-col
          ${data ? trustCfg.border : 'border-gray-700/60'}
        `}
        style={{
          maxHeight: 'min(90vh, 760px)',
          animation: 'dim-slide 240ms cubic-bezier(0.16,1,0.3,1) both',
        }}
      >

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className={`
          px-5 py-4 flex items-center gap-3 border-b shrink-0
          bg-gradient-to-r ${data ? `${trustCfg.bannerBg}` : 'bg-gray-800/40'}
          ${data ? trustCfg.bannerBorder : 'border-gray-800'}
        `}>

          {/* Device type icon bubble */}
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${data ? `${typeCfg.bg} ${typeCfg.border} border` : 'bg-gray-800 border border-gray-700'}`}>
            <TypeIcon size={18} className={data ? typeCfg.color : 'text-gray-500'} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-bold text-gray-100 tracking-widest">{mac}</span>
              {data && !loading && (
                <span className={`text-xs px-2 py-0.5 rounded-md border font-medium ${confCfg.className}`}>
                  {confCfg.label} confidence
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 truncate mt-0.5">
              {loading
                ? 'Analyzing device intelligence…'
                : data
                  ? `${data.vendor || 'Unknown vendor'} · ${data.deviceType || 'Unknown type'}`
                  : 'MAC Intelligence'}
            </p>
          </div>

          {/* Trust badge */}
          {data && !loading && (
            <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-bold shrink-0 ${trustCfg.bg} ${trustCfg.border} ${trustCfg.text}`}>
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${trustCfg.dot} ${trustKey === 'suspicious' || trustKey === 'blocked' ? 'animate-pulse' : ''}`} />
              {trustCfg.label}
            </span>
          )}

          <button
            onClick={onClose}
            className="w-7 h-7 rounded-lg flex items-center justify-center text-gray-500 hover:text-gray-200 hover:bg-gray-700/70 transition-colors ml-1 shrink-0"
            aria-label="Close"
          >
            <X size={14} />
          </button>
        </div>

        {/* ── Body ───────────────────────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-4 min-h-0">

          {/* Loading */}
          {loading && (
            <div className="flex flex-col items-center justify-center py-20 gap-3 text-gray-500">
              <Loader2 size={30} className="animate-spin text-blue-400" />
              <p className="text-sm">Running intelligence analysis…</p>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2.5 p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
              <AlertTriangle size={14} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {data && !loading && (
            <>
              {/* ── Section 1: Device Overview ──────────────────────────── */}
              <Section title="Device Overview" icon={<Monitor size={13} className="text-blue-400" />}>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                  <MiniCard label="OUI Prefix">
                    <span className="font-mono text-xs text-gray-100">{data.oui}</span>
                  </MiniCard>
                  <MiniCard label="Vendor">
                    <span className="text-xs text-gray-100 font-semibold truncate">{data.vendor}</span>
                  </MiniCard>
                  <MiniCard label="Device Type">
                    <div className="flex items-center gap-1.5">
                      <TypeIcon size={12} className={typeCfg.color} />
                      <span className="text-xs text-gray-100 font-semibold">{data.deviceType}</span>
                    </div>
                  </MiniCard>
                  <MiniCard label="OS Hints">
                    {data.osHints?.length > 0
                      ? <div className="flex flex-wrap gap-1">
                          {data.osHints.map((o) => (
                            <span key={o} className="text-xs px-1.5 py-0.5 rounded bg-gray-700/60 text-gray-300 font-mono">{o}</span>
                          ))}
                        </div>
                      : <span className="text-xs text-gray-600">—</span>
                    }
                  </MiniCard>
                </div>
              </Section>

              {/* ── Section 2: Security Analysis ────────────────────────── */}
              <Section title="Security Analysis" icon={<ShieldAlert size={13} className="text-red-400" />}>

                {/* Risk Score bar */}
                <div className="rounded-xl bg-gray-800/60 border border-gray-700/50 p-3.5 mb-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Risk Score</span>
                    <div className="flex items-center gap-2">
                      <span className={`text-xl font-black tabular-nums ${alertCfg.text}`}>{data.riskScore}</span>
                      <span className="text-xs text-gray-600">/ 100</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-bold border ${alertCfg.text} ${alertCfg.track} border-current/30`}>
                        {alertCfg.label}
                      </span>
                    </div>
                  </div>
                  <div className="h-2.5 rounded-full bg-gray-700/60 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${alertCfg.bar}`}
                      style={{ width: `${data.riskScore}%` }}
                    />
                  </div>
                </div>

                {/* Threat indicators */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <ThreatChip
                    ok={!data.spoofingDetected}
                    label={data.spoofingDetected ? 'MAC Randomized / Spoofed' : 'No Spoofing Detected'}
                    detail={data.spoofingReason}
                  />
                  <ThreatChip
                    ok={!data.duplicateDetected}
                    label={data.duplicateDetected ? 'Duplicate MAC Detected' : 'No MAC Conflict'}
                    detail={data.duplicateDetected ? 'Same MAC active on multiple IPs' : null}
                  />
                  <ThreatChip
                    ok={!data.vendorMismatch}
                    label={data.vendorMismatch ? 'Vendor / OS Mismatch' : 'Vendor Profile Normal'}
                    detail={data.vendorMismatch ? 'Vendor type contradicts observed OS behavior' : null}
                  />
                </div>
              </Section>

              {/* ── Section 3: Network Identity ──────────────────────────── */}
              <Section title="Network Identity" icon={<Globe size={13} className="text-purple-400" />}>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">

                  {/* Identity cards */}
                  <div className="flex flex-col gap-2">
                    <InfoPair icon={<MapPin size={11} />}  label="Current IP"
                      value={
                        data.currentIp
                          ? <div className="flex items-center gap-1.5">
                              <span className="font-mono text-xs text-gray-100">{data.currentIp}</span>
                              {onViewDevice && (
                                <button
                                  onClick={() => onViewDevice(data.currentIp)}
                                  className="text-blue-400 hover:text-blue-300 transition-colors"
                                  title="Open device scan"
                                >
                                  <ExternalLink size={11} />
                                </button>
                              )}
                            </div>
                          : <span className="text-gray-600 text-xs">—</span>
                      }
                    />
                    <InfoPair icon={<Server size={11} />}   label="Hostname"  value={<span className="text-xs text-gray-100">{data.hostname || '—'}</span>} />
                    <InfoPair icon={<Globe size={11} />}    label="Subnet"    value={<span className="font-mono text-xs text-gray-100">{data.subnet || '—'}</span>} />
                    <InfoPair icon={<Hash size={11} />}     label="MAC Full"  value={<span className="font-mono text-xs text-gray-300 tracking-wider">{mac}</span>} />
                    {data.openPorts?.length > 0 && (
                      <InfoPair icon={<Zap size={11} />} label="Open Ports"
                        value={
                          <div className="flex flex-wrap gap-1">
                            {data.openPorts.map((p) => (
                              <span key={p} className="font-mono text-xs px-1.5 py-0.5 rounded bg-blue-500/15 border border-blue-500/25 text-blue-300">{p}</span>
                            ))}
                          </div>
                        }
                      />
                    )}
                  </div>

                  {/* IP History table */}
                  <div className="rounded-xl bg-gray-800/50 border border-gray-700/50 overflow-hidden">
                    <div className="flex items-center gap-1.5 px-3 py-2 border-b border-gray-700/50">
                      <Database size={11} className="text-gray-500" />
                      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide">IP History</span>
                      <span className="ml-auto text-xs text-gray-600">{data.ipHistory?.length || 0} record{data.ipHistory?.length !== 1 ? 's' : ''}</span>
                    </div>
                    <div className="max-h-32 overflow-y-auto">
                      {data.ipHistory?.length > 0 ? (
                        <table className="w-full text-xs">
                          <tbody className="divide-y divide-gray-800/60">
                            {data.ipHistory.map((entry, i) => (
                              <tr key={i} className="hover:bg-gray-700/20 transition-colors">
                                <td className="px-3 py-1.5 font-mono text-gray-200">{entry.ip}</td>
                                <td className="px-2 py-1.5 text-gray-500 text-right tabular-nums">{entry.count}×</td>
                                <td className="px-3 py-1.5 text-gray-600 text-right">{fmtDate(entry.lastSeen)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        <p className="text-xs text-gray-600 px-3 py-3">No history yet</p>
                      )}
                    </div>
                  </div>
                </div>
              </Section>

              {/* ── Section 4: Device History ────────────────────────────── */}
              <Section title="Device History" icon={<Clock size={13} className="text-gray-400" />}>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                  <StatCard label="First Detected"  value={data.firstSeen  ? fmtDate(data.firstSeen)  : '—'} />
                  <StatCard label="Last Seen"        value={data.lastSeen   ? fmtDate(data.lastSeen)   : '—'} />
                  <StatCard label="Total Connections" value={
                    data.connectionCount > 0
                      ? <span className="text-xl font-black tabular-nums">{data.connectionCount}</span>
                      : '—'
                  } />
                  <StatCard label="Reconnect Pattern" value={
                    <span className="capitalize text-xs font-semibold text-gray-200">{data.reconnectFrequency || '—'}</span>
                  } />
                </div>
                {data.sessionDurationAvg != null && (
                  <p className="text-xs text-gray-600 mt-2">
                    Avg time between first and last sighting per connection window: <span className="text-gray-400">{fmtDuration(data.sessionDurationAvg)}</span>
                  </p>
                )}
              </Section>

              {/* ── Section 5: Behavior Pattern ──────────────────────────── */}
              <Section title="Behavior Analysis" icon={<Activity size={13} className="text-blue-400" />}>
                <div className="flex flex-col gap-3">

                  {/* Pattern summary */}
                  <div className="flex items-start gap-3">
                    <div className="flex flex-col gap-0.5 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-bold text-gray-100">{data.activityPattern?.label}</span>
                        {data.activityPattern?.unusualActivity && (
                          <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-orange-500/15 border border-orange-500/30 text-orange-400 font-semibold">
                            <AlertTriangle size={10} />
                            Unusual Activity
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-gray-500">{data.activityPattern?.description}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-xs text-gray-600 mb-0.5">Pattern score</div>
                      <div className="text-lg font-black text-gray-200 tabular-nums">{data.activityPattern?.score ?? '—'}</div>
                    </div>
                  </div>

                  {/* 24-hour activity heatmap */}
                  <HeatMap hours={data.activityPattern?.hours || new Array(24).fill(0)} />

                </div>
              </Section>
            </>
          )}
        </div>

        {/* ── Footer ─────────────────────────────────────────────────────── */}
        <div className="px-5 py-3.5 border-t border-gray-800 flex items-center gap-2.5 bg-gray-900/90 shrink-0">
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold
              bg-gray-800 hover:bg-gray-700 border border-gray-700/60
              text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed
              transition-all duration-150"
          >
            {loading
              ? <><Loader2 size={12} className="animate-spin" /> Analyzing…</>
              : <><RefreshCw size={12} /> Rescan Intelligence</>}
          </button>

          {onViewDevice && data?.currentIp && (
            <button
              onClick={() => onViewDevice(data.currentIp)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold
                bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30
                text-blue-300 transition-all duration-150"
            >
              <ExternalLink size={12} />
              View Device Scan
            </button>
          )}

          <button
            onClick={onClose}
            className="ml-auto flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold
              bg-gray-800 hover:bg-gray-700 border border-gray-700/60
              text-gray-400 hover:text-gray-200 transition-all duration-150"
          >
            <X size={12} />
            Close
          </button>
        </div>

      </div>

      {/* Keyframe animations */}
      <style>{`
        @keyframes dim-fade  { from { opacity: 0 } to { opacity: 1 } }
        @keyframes dim-slide { from { opacity: 0; transform: translateY(22px) scale(0.95) } to { opacity: 1; transform: none } }
      `}</style>
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Section({ title, icon, children }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-2.5">
        {icon}
        <span className="text-xs font-bold text-gray-400 uppercase tracking-widest">{title}</span>
        <div className="flex-1 h-px bg-gray-800 ml-2" />
      </div>
      {children}
    </div>
  );
}

function MiniCard({ label, children }) {
  return (
    <div className="rounded-xl bg-gray-800/50 border border-gray-700/50 p-3 flex flex-col gap-1 min-w-0">
      <span className="text-xs text-gray-600 uppercase tracking-wide font-medium truncate">{label}</span>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function StatCard({ label, value }) {
  return (
    <div className="rounded-xl bg-gray-800/50 border border-gray-700/50 p-3 flex flex-col gap-1">
      <span className="text-xs text-gray-600 uppercase tracking-wide font-medium">{label}</span>
      <div className="text-sm font-bold text-gray-200 tabular-nums">{value}</div>
    </div>
  );
}

function ThreatChip({ ok, label, detail }) {
  return (
    <div className={`flex items-start gap-2 p-2.5 rounded-xl border ${
      ok
        ? 'bg-green-500/8 border-green-500/20'
        : 'bg-red-500/10 border-red-500/30'
    }`}>
      <div className={`mt-0.5 shrink-0 ${ok ? 'text-green-400' : 'text-red-400'}`}>
        {ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
      </div>
      <div className="min-w-0">
        <p className={`text-xs font-semibold leading-tight ${ok ? 'text-green-300' : 'text-red-300'}`}>{label}</p>
        {detail && <p className="text-xs text-gray-600 mt-0.5 leading-tight">{detail}</p>}
      </div>
    </div>
  );
}

function InfoPair({ icon, label, value }) {
  return (
    <div className="flex items-start gap-2">
      <div className="text-gray-600 mt-0.5 shrink-0">{icon}</div>
      <div className="flex-1 min-w-0">
        <div className="text-xs text-gray-600 leading-none mb-0.5">{label}</div>
        <div>{value}</div>
      </div>
    </div>
  );
}

// ─── 24-hour heatmap ─────────────────────────────────────────────────────────

function HeatMap({ hours }) {
  const max = Math.max(...hours, 1);
  const labels = ['00', '03', '06', '09', '12', '15', '18', '21'];

  return (
    <div>
      <div className="flex gap-0.5">
        {hours.map((count, h) => {
          const alpha = count > 0 ? 0.12 + (count / max) * 0.88 : 0;
          return (
            <div
              key={h}
              title={`${String(h).padStart(2, '0')}:00 — ${count} connection${count !== 1 ? 's' : ''}`}
              className="flex-1 rounded-sm cursor-default transition-opacity duration-200"
              style={{
                height: '32px',
                backgroundColor: count > 0
                  ? `rgba(59,130,246,${alpha})`
                  : 'rgba(55,65,81,0.25)',
              }}
            />
          );
        })}
      </div>
      {/* Hour labels at 3-hour intervals */}
      <div className="flex mt-1">
        {labels.map((l, i) => (
          <div key={l} className="text-gray-700 text-xs" style={{ flex: '3', textAlign: i === 0 ? 'left' : 'center' }}>
            {l}
          </div>
        ))}
        <div className="text-gray-700 text-xs" style={{ flex: '3', textAlign: 'right' }}>24</div>
      </div>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    month: '2-digit', day: '2-digit', year: '2-digit',
    hour: '2-digit', minute: '2-digit',
  });
}

function fmtDuration(seconds) {
  if (!seconds || seconds < 0) return '—';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}
