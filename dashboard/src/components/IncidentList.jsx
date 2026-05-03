import React, { useState, useEffect, useCallback } from 'react';
import { fetchIncidents } from '../lib/api';
import { connectSocket } from '../lib/socket';
import IncidentCard from './IncidentCard';
import { Filter, RefreshCw, Wifi, WifiOff } from 'lucide-react';

const FILTER_OPTIONS = {
  status:   ['', 'open', 'in_progress', 'mitigating', 'closed'],
  severity: ['', 'critical', 'high', 'medium', 'low'],
  category: ['', 'phishing', 'ransomware', 'device_loss', 'data_breach', 'suspicious_activity', 'other'],
};

const LABEL_MAP = {
  '': 'Tous',
  open: 'Ouvert', in_progress: 'En cours', mitigating: 'Mitigation', closed: 'Fermé',
  critical: 'Critique', high: 'Élevé', medium: 'Moyen', low: 'Faible',
  phishing: 'Phishing', ransomware: 'Ransomware', device_loss: 'Perte',
  data_breach: 'Fuite', suspicious_activity: 'Suspect', other: 'Autre',
};

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
      if (!incident?.id) {
        load();
        return;
      }

      // Mark as new and fetch canonical row from API to avoid partial socket payload issues.
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
      {/* Filters */}
      <div className="p-4 border-b border-gray-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-gray-400" />
            <span className="text-gray-400 text-sm font-medium">Filtres</span>
            <span className="text-gray-600 text-xs">({total} incidents)</span>
          </div>
          <div className="flex items-center gap-2">
            {connected
              ? <Wifi size={14} className="text-green-400" />
              : <WifiOff size={14} className="text-red-400" />
            }
            <button onClick={load} className="btn-ghost p-1" title="Actualiser">
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          {Object.entries(FILTER_OPTIONS).map(([key, opts]) => (
            <select
              key={key}
              value={filters[key]}
              onChange={e => setFilters(f => ({ ...f, [key]: e.target.value }))}
              className="bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded-lg px-2 py-1.5 focus:outline-none focus:border-gray-500"
            >
              {opts.map(opt => (
                <option key={opt} value={opt}>{LABEL_MAP[opt] || opt || `${key} (tous)`}</option>
              ))}
            </select>
          ))}
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {loading && incidents.length === 0 && (
          <div className="text-center text-gray-500 py-12">Chargement…</div>
        )}
        {!loading && incidents.length === 0 && (
          <div className="text-center text-gray-500 py-12">
            <p className="text-4xl mb-3">🎉</p>
            <p>Aucun incident</p>
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
