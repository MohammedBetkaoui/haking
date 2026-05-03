import React, { useState, useEffect, useCallback } from 'react';
import { fetchIncidents } from '../lib/api';
import { connectSocket } from '../lib/socket';
import IncidentCard from './IncidentCard';
import { RefreshCw, Wifi, WifiOff } from 'lucide-react';

// ── Filter groups ────────────────────────────────────────────────────────────
const FILTER_GROUPS = [
  {
    key: 'status',
    options: [
      { value: '',            label: 'Tous' },
      { value: 'open',        label: 'Ouvert' },
      { value: 'in_progress', label: 'En cours' },
      { value: 'mitigating',  label: 'Mitigation' },
      { value: 'closed',      label: 'Fermé' },
    ],
  },
  {
    key: 'severity',
    options: [
      { value: '',         label: 'Toutes' },
      { value: 'critical', label: '🔴 Critique' },
      { value: 'high',     label: '🟠 Élevé' },
      { value: 'medium',   label: '🟡 Moyen' },
      { value: 'low',      label: '🟢 Faible' },
    ],
  },
];

// ── Skeleton card ────────────────────────────────────────────────────────────
function SkeletonCard() {
  return (
    <div className="card p-4 border-l-2 border-l-gray-700 space-y-2.5 animate-pulse">
      <div className="flex gap-2">
        <div className="skeleton h-4 w-14 rounded-full" />
        <div className="skeleton h-4 w-16 rounded-full" />
        <div className="skeleton h-4 w-12 rounded-full" />
      </div>
      <div className="skeleton h-4 w-3/4 rounded" />
      <div className="skeleton h-3 w-1/2 rounded" />
    </div>
  );
}

export default function IncidentList({ onSelect, selectedId, refreshSignal }) {
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [newIds, setNewIds] = useState(new Set());
  const [connected, setConnected] = useState(false);
  const [filters, setFilters] = useState({ status: '', severity: '', category: '' });

  const load = useCallback(() => {
    setLoading(true);
    const params = Object.fromEntries(Object.entries(filters).filter(([, v]) => v));
    fetchIncidents(params)
      .then(({ incidents, total }) => {
        setIncidents(incidents);
        setTotal(total);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [filters]);

  useEffect(() => { load(); }, [load, refreshSignal]);

  // Real-time socket
  useEffect(() => {
    const socket = connectSocket();
    setConnected(socket.connected);

    const handleConnect = () => setConnected(true);
    const handleDisconnect = () => setConnected(false);
    const handleNewIncident = (incident) => {
      if (!incident?.id) { load(); return; }
      setNewIds(ids => new Set([...ids, incident.id]));
      setTimeout(() => setNewIds(ids => {
        const next = new Set(ids);
        next.delete(incident.id);
        return next;
      }), 10000);
      load();
    };
    const handleIncidentUpdated = (payload) => {
      setIncidents(prev => prev.map(inc => inc.id === payload.id ? { ...inc, ...payload } : inc));
    };

    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('incident:new', handleNewIncident);
    socket.on('incident:updated', handleIncidentUpdated);

    return () => {
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('incident:new', handleNewIncident);
      socket.off('incident:updated', handleIncidentUpdated);
    };
  }, [load]);

  return (
    <div className="flex flex-col h-full">
      {/* Header bar */}
      <div className="px-4 pt-4 pb-3 border-b border-gray-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-gray-200 text-sm font-semibold">Incidents</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400 border border-gray-700 font-mono">
              {total}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span title={connected ? 'Temps réel actif' : 'Déconnecté'}>
              {connected
                ? <Wifi size={13} className="text-green-400" />
                : <WifiOff size={13} className="text-red-400" />
              }
            </span>
            <button
              onClick={load}
              className="text-gray-500 hover:text-gray-200 hover:bg-gray-800 p-1.5 rounded-lg transition-all"
              title="Actualiser"
            >
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>

        {/* Pill filter groups */}
        <div className="space-y-2">
          {FILTER_GROUPS.map(({ key, options }) => (
            <div key={key} className="flex gap-1 flex-wrap">
              {options.map(({ value, label }) => (
                <button
                  key={value}
                  onClick={() => setFilters(f => ({ ...f, [key]: value }))}
                  className={`text-xs px-2.5 py-1 rounded-full border transition-all duration-100 whitespace-nowrap ${
                    filters[key] === value
                      ? 'bg-blue-500/20 border-blue-500/40 text-blue-300 font-medium'
                      : 'bg-gray-800/50 border-gray-700/60 text-gray-400 hover:text-gray-200 hover:border-gray-600'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {loading && incidents.length === 0 && (
          <>
            <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
          </>
        )}
        {!loading && incidents.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <span className="text-4xl mb-3 opacity-60">🎉</span>
            <p className="text-gray-400 font-medium text-sm">Aucun incident</p>
            <p className="text-gray-600 text-xs mt-1">Tous les filtres appliqués</p>
          </div>
        )}
        {incidents.map(inc => (
          <IncidentCard
            key={inc.id}
            incident={inc}
            onClick={onSelect}
            isNew={newIds.has(inc.id)}
          />
        ))}
      </div>
    </div>
  );
}
