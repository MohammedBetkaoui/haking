import React, { useCallback, useEffect, useState } from 'react';

import { fetchIncidents } from '../lib/api';
import { connectSocket, disconnectSocket } from '../lib/socket';
import IncidentCard from './IncidentCard';

function SlaLane({ title, incidents, loading, emptyLabel, onSelect }) {
  return (
    <div className="card overflow-hidden flex flex-col min-h-0">
      <div className="px-5 py-4 border-b border-gray-800 bg-gray-900/80">
        <div className="flex items-center justify-between gap-4">
          <h3 className="text-gray-100 font-semibold">{title}</h3>
          <span className="text-gray-500 text-xs">{incidents.length} incidents</span>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {loading && incidents.length === 0 && (
          <div className="text-center text-gray-500 py-10">Chargement…</div>
        )}
        {!loading && incidents.length === 0 && (
          <div className="text-center text-gray-500 py-10">{emptyLabel}</div>
        )}
        {incidents.map((incident) => (
          <IncidentCard
            key={incident.id}
            incident={incident}
            onClick={onSelect}
          />
        ))}
      </div>
    </div>
  );
}

export default function SlaBoard({ onSelect, refreshSignal }) {
  const [warningIncidents, setWarningIncidents] = useState([]);
  const [breachedIncidents, setBreachedIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);

    Promise.all([
      fetchIncidents({ workflow_state: 'warning', limit: 25 }),
      fetchIncidents({ workflow_state: 'breached', limit: 25 }),
    ])
      .then(([warningPayload, breachPayload]) => {
        setWarningIncidents(warningPayload.incidents || []);
        setBreachedIncidents(breachPayload.incidents || []);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load, refreshSignal]);

  useEffect(() => {
    const socket = connectSocket();

    socket.on('incident:updated', (payload) => {
      if (!payload?.id) {
        return;
      }

      const mergePayload = (current) => current.map((incident) => (
        incident.id === payload.id ? { ...incident, ...payload } : incident
      ));

      setWarningIncidents((current) => {
        const merged = mergePayload(current).filter((incident) => incident.workflow_state === 'warning');
        return merged;
      });

      setBreachedIncidents((current) => {
        const merged = mergePayload(current).filter((incident) => incident.workflow_state === 'breached');
        return merged;
      });

      if (payload.workflow_state === 'warning' || payload.workflow_state === 'breached') {
        load();
      }
    });

    return () => disconnectSocket();
  }, [load]);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 h-full min-h-0">
      <SlaLane
        title="Proches SLA"
        incidents={warningIncidents}
        loading={loading}
        emptyLabel="Aucun incident en zone de warning SLA."
        onSelect={onSelect}
      />
      <SlaLane
        title="SLA dépassés"
        incidents={breachedIncidents}
        loading={loading}
        emptyLabel="Aucun incident en dépassement SLA."
        onSelect={onSelect}
      />
    </div>
  );
}