import React, { useEffect, useState, useCallback } from 'react';
import {
  X, Shield, ShieldAlert, ShieldCheck, Cpu, Globe,
  Monitor, Wifi, Clock, Server, Hash, MapPin, Loader2,
  ScanLine, CheckCircle2, AlertTriangle, ChevronRight, Router,
} from 'lucide-react';
import { fetchDeviceDetails, addTrustedDevice } from '../lib/api';

// ─── Trust Status Config ──────────────────────────────────────────────────────

const TRUST_CONFIG = {
  trusted: {
    label: 'Trusted',
    bg: 'bg-green-500/10',
    border: 'border-green-500/40',
    text: 'text-green-400',
    ring: 'ring-green-500/20',
    icon: ShieldCheck,
    dot: 'bg-green-500',
    headerGrad: 'from-green-500/5 to-transparent border-green-500/20',
  },
  unknown: {
    label: 'Unknown',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/40',
    text: 'text-yellow-400',
    ring: 'ring-yellow-500/20',
    icon: Shield,
    dot: 'bg-yellow-500',
    headerGrad: 'from-yellow-500/5 to-transparent border-yellow-500/20',
  },
  suspicious: {
    label: 'Suspicious',
    bg: 'bg-red-500/10',
    border: 'border-red-500/40',
    text: 'text-red-400',
    ring: 'ring-red-500/20',
    icon: ShieldAlert,
    dot: 'bg-red-500',
    headerGrad: 'from-red-500/5 to-transparent border-red-500/20',
  },
};

const DEVICE_TYPE_ICON = {
  'PC / Server': Monitor,
  'Router':      Wifi,
  'Mobile':      Globe,
  'IoT Device':  Cpu,
  'Unknown':     Server,
};

// ─── Component ────────────────────────────────────────────────────────────────

/**
 * DeviceDetailsModal
 *
 * Props:
 *   ip      — IP address string to inspect
 *   onClose — callback to close the modal
 */
export default function DeviceDetailsModal({ ip, onClose }) {
  const [data,         setData]         = useState(null);
  const [loading,      setLoading]      = useState(true);
  const [scanning,     setScanning]     = useState(false);
  const [trustLoading, setTrustLoading] = useState(false);
  const [error,        setError]        = useState(null);
  const [trustSuccess, setTrustSuccess] = useState(false);

  // ── Fetch device details ──────────────────────────────────────────────────
  const loadDetails = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchDeviceDetails(ip);
      setData(result);
    } catch (err) {
      setError(err?.response?.data?.error || 'Failed to fetch device details.');
    } finally {
      setLoading(false);
    }
  }, [ip]);

  useEffect(() => { loadDetails(); }, [loadDetails]);

  // ── Escape key closes modal ───────────────────────────────────────────────
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  // ── Handlers ─────────────────────────────────────────────────────────────
  const handleScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const result = await fetchDeviceDetails(ip);
      setData(result);
    } catch (err) {
      setError(err?.response?.data?.error || 'Scan failed.');
    } finally {
      setScanning(false);
    }
  };

  const handleAddTrusted = async () => {
    if (!data?.mac || data.mac === 'N/A') return;
    setTrustLoading(true);
    setError(null);
    try {
      await addTrustedDevice(data.mac);
      setData((prev) => ({ ...prev, trusted: 'trusted' }));
      setTrustSuccess(true);
      setTimeout(() => setTrustSuccess(false), 4000);
    } catch (err) {
      setError(err?.response?.data?.error || 'Failed to add device to trusted list.');
    } finally {
      setTrustLoading(false);
    }
  };

  // ── Derived UI values ─────────────────────────────────────────────────────
  const trustKey  = data?.trusted && TRUST_CONFIG[data.trusted] ? data.trusted : 'unknown';
  const trustCfg  = TRUST_CONFIG[trustKey];
  const TrustIcon = trustCfg.icon;
  const DeviceIcon = DEVICE_TYPE_ICON[data?.deviceType] || Server;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm"
      style={{ animation: 'ddm-fade 150ms ease-out both' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className={`
          relative w-full max-w-lg mx-4 bg-gray-900
          border rounded-2xl shadow-2xl overflow-hidden
          ${data ? trustCfg.border : 'border-gray-700/60'}
          ${data ? `ring-1 ${trustCfg.ring}` : ''}
        `}
        style={{ animation: 'ddm-slide 220ms cubic-bezier(0.16,1,0.3,1) both' }}
      >

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div
          className={`
            px-5 py-4 flex items-center gap-3 border-b bg-gradient-to-r
            ${data ? `${trustCfg.headerGrad}` : 'from-gray-800/40 to-transparent border-gray-800'}
          `}
        >
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${data ? trustCfg.bg : 'bg-gray-800'}`}>
            <Monitor size={15} className={data ? trustCfg.text : 'text-gray-400'} />
          </div>

          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-gray-100 font-mono tracking-wide">{ip}</h2>
            <p className="text-xs text-gray-500 truncate">
              {loading
                ? 'Loading device info…'
                : data?.hostname && data.hostname !== ip
                  ? data.hostname
                  : 'Device Details'}
            </p>
          </div>

          {/* Trust badge */}
          {data && !loading && (
            <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-semibold ${trustCfg.bg} ${trustCfg.border} ${trustCfg.text}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${trustCfg.dot} ${trustKey === 'suspicious' ? 'animate-pulse' : ''}`} />
              {trustCfg.label}
            </span>
          )}

          <button
            onClick={onClose}
            className="ml-1 w-7 h-7 rounded-lg flex items-center justify-center text-gray-500 hover:text-gray-200 hover:bg-gray-700/70 transition-colors"
            aria-label="Close"
          >
            <X size={14} />
          </button>
        </div>

        {/* ── Body ───────────────────────────────────────────────────────── */}
        <div className="p-5 max-h-[60vh] overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-gray-700">

          {/* Loading */}
          {loading && (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-gray-500">
              <Loader2 size={28} className="animate-spin text-blue-400" />
              <p className="text-sm">Scanning device…</p>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2.5 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs mb-4">
              <AlertTriangle size={14} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Data */}
          {data && !loading && (
            <div className="flex flex-col gap-4">

              {/* Alert banners */}
              {trustKey === 'suspicious' && (
                <div className="flex items-start gap-2.5 px-3.5 py-3 rounded-xl bg-red-500/10 border border-red-500/30">
                  <ShieldAlert size={14} className="text-red-400 shrink-0 mt-0.5 animate-pulse" />
                  <p className="text-xs text-red-300 leading-relaxed">
                    This device was flagged as <span className="font-bold">suspicious</span> — it appeared
                    after the baseline scan and is not on the trusted list.
                  </p>
                </div>
              )}

              {trustKey === 'unknown' && (
                <div className="flex items-start gap-2.5 px-3.5 py-3 rounded-xl bg-yellow-500/10 border border-yellow-500/30">
                  <Shield size={14} className="text-yellow-400 shrink-0 mt-0.5" />
                  <p className="text-xs text-yellow-300 leading-relaxed">
                    Trust status is <span className="font-bold">unknown</span>. Review device details
                    before adding to the trusted list.
                  </p>
                </div>
              )}

              {trustSuccess && (
                <div className="flex items-center gap-2.5 px-3.5 py-3 rounded-xl bg-green-500/10 border border-green-500/30">
                  <CheckCircle2 size={14} className="text-green-400 shrink-0" />
                  <p className="text-xs text-green-300">
                    MAC address <span className="font-mono font-bold">{data.mac}</span> added to trusted devices.
                  </p>
                </div>
              )}

              {/* Info grid */}
              <div className="grid grid-cols-2 gap-2.5">
                <InfoCard
                  icon={<MapPin size={11} />}
                  label="IP Address"
                  value={data.ip}
                  mono
                  accent={trustKey === 'suspicious' ? 'red' : trustKey === 'trusted' ? 'green' : undefined}
                />
                <InfoCard icon={<Hash size={11} />}     label="MAC Address"           value={data.mac}        mono />
                <InfoCard icon={<Server size={11} />}   label="Hostname"               value={data.hostname || '—'} />
                <InfoCard icon={<Globe size={11} />}    label="Vendor / Manufacturer"  value={data.vendor || '—'} />
                <InfoCard icon={<DeviceIcon size={11} />} label="Device Type"          value={data.deviceType || '—'} />
                <InfoCard icon={<Monitor size={11} />}  label="Operating System"       value={data.os || '—'} />
              </div>

              {/* Open ports */}
              <div className="rounded-xl bg-gray-800/50 border border-gray-700/50 p-3.5">
                <div className="flex items-center gap-1.5 mb-2.5">
                  <ChevronRight size={12} className="text-blue-400" />
                  <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Open Ports</span>
                </div>
                {data.openPorts?.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {data.openPorts.map((port) => (
                      <span
                        key={port}
                        className="font-mono text-xs px-2 py-0.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-300"
                      >
                        {port}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-xs text-gray-600">No open ports detected</span>
                )}
              </div>

              {/* Timestamps */}
              <div className="grid grid-cols-2 gap-2.5">
                <InfoCard
                  icon={<Clock size={11} />}
                  label="First Detected"
                  value={data.firstSeen ? fmtDateTime(data.firstSeen) : '—'}
                />
                <InfoCard
                  icon={<Clock size={11} />}
                  label="Last Seen"
                  value={data.lastSeen ? fmtDateTime(data.lastSeen) : '—'}
                />
              </div>

            </div>
          )}
        </div>

        {/* ── Footer actions ──────────────────────────────────────────────── */}
        <div className="px-5 py-4 border-t border-gray-800 flex items-center gap-3 bg-gray-900/90">
          <button
            onClick={handleScan}
            disabled={scanning || loading}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl
              bg-blue-600 hover:bg-blue-500 active:bg-blue-700
              disabled:opacity-50 disabled:cursor-not-allowed
              text-white text-sm font-semibold transition-all duration-150"
          >
            {scanning
              ? <><Loader2 size={13} className="animate-spin" /> Scanning…</>
              : <><ScanLine size={13} /> Scan Device</>}
          </button>

          <button
            onClick={handleAddTrusted}
            disabled={
              trustLoading || loading || !data ||
              data.mac === 'N/A' || trustKey === 'trusted'
            }
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl
              bg-green-800/50 hover:bg-green-700/60 active:bg-green-900/60
              disabled:opacity-40 disabled:cursor-not-allowed
              text-green-200 text-sm font-semibold border border-green-600/30
              transition-all duration-150"
          >
            {trustLoading
              ? <><Loader2 size={13} className="animate-spin" /> Saving…</>
              : trustKey === 'trusted'
                ? <><CheckCircle2 size={13} /> Already Trusted</>
                : <><ShieldCheck size={13} /> Add to Trusted Devices</>}
          </button>
        </div>

      </div>

      {/* Keyframe animations */}
      <style>{`
        @keyframes ddm-fade  { from { opacity: 0 }                               to { opacity: 1 } }
        @keyframes ddm-slide { from { opacity: 0; transform: translateY(18px) scale(0.96) } to { opacity: 1; transform: none } }
      `}</style>
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function InfoCard({ icon, label, value, mono, accent }) {
  const accentClass = {
    red:   'border-red-500/20   bg-red-500/5',
    green: 'border-green-500/20 bg-green-500/5',
  }[accent] ?? 'border-gray-700/50 bg-gray-800/50';

  return (
    <div className={`rounded-xl p-3 border ${accentClass} flex flex-col gap-1 min-w-0`}>
      <div className="flex items-center gap-1.5 text-gray-500">
        {icon}
        <span className="text-xs uppercase tracking-wide font-medium truncate">{label}</span>
      </div>
      <span className={`text-gray-100 font-semibold truncate ${mono ? 'font-mono text-xs' : 'text-sm'}`}>
        {value}
      </span>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDateTime(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    month: '2-digit', day: '2-digit',
    hour: '2-digit',  minute: '2-digit',
  });
}
