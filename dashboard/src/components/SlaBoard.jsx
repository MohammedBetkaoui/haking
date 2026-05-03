import React, { useCallback, useEffect, useState } from 'react';

import { fetchIncidents, fetchPortCheckReport, runPortCheck } from '../lib/api';
import { connectSocket, disconnectSocket } from '../lib/socket';
import IncidentCard from './IncidentCard';

function parseMetadata(metadata) {
  if (!metadata) return {};
  if (typeof metadata === 'string') {
    try {
      return JSON.parse(metadata);
    } catch (_) {
      return {};
    }
  }
  return metadata;
}

function isOpenPortIncident(incident) {
  const metadata = parseMetadata(incident.metadata);
  return metadata.rule === 2 || incident.title?.toLowerCase().includes('port inhabituel');
}

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
  const [suspiciousAccessIncidents, setSuspiciousAccessIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshingSystem, setRefreshingSystem] = useState(false);
  const [lastCheckSummary, setLastCheckSummary] = useState(null);

  const load = useCallback(() => {
    setLoading(true);

    Promise.all([
      fetchIncidents({ workflow_state: 'warning', limit: 25 }),
      fetchIncidents({ workflow_state: 'breached', limit: 25 }),
      fetchPortCheckReport(25),
    ])
      .then(([warningPayload, breachPayload, portReportPayload]) => {
        setWarningIncidents(warningPayload.incidents || []);
        setBreachedIncidents(breachPayload.incidents || []);
        setSuspiciousAccessIncidents(portReportPayload.incidents || []);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleRefreshSystem = useCallback(async () => {
    setRefreshingSystem(true);
    try {
      const result = await runPortCheck();
      const openCount = result.open?.length || 0;
      const abnormalCount = result.abnormal?.length || 0;
      const scanned = result.scanned || 0;
      const openPercent = scanned > 0 ? ((openCount / scanned) * 100) : 0;
      const abnormalPercent = openCount > 0 ? ((abnormalCount / openCount) * 100) : 0;

      setLastCheckSummary({
        scanned,
        openCount,
        abnormalCount,
        openPercent,
        abnormalPercent,
        targetIp: result.target_ip || 'local',
        at: new Date().toISOString(),
      });
      load();
    } catch (error) {
      console.error(error);
    } finally {
      setRefreshingSystem(false);
    }
  }, [load]);

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

    socket.on('scan:port-check:done', (payload) => {
      if (!payload) return;
      const openCount = payload.open?.length || 0;
      const abnormalCount = payload.abnormal?.length || 0;
      const scanned = payload.scanned || 0;

      setLastCheckSummary({
        scanned,
        openCount,
        abnormalCount,
        openPercent: scanned > 0 ? ((openCount / scanned) * 100) : 0,
        abnormalPercent: openCount > 0 ? ((abnormalCount / openCount) * 100) : 0,
        targetIp: payload.target_ip || 'local',
        at: payload.ts || new Date().toISOString(),
      });
      load();
    });

    return () => disconnectSocket();
  }, [load]);

  const allSlaIncidents = [...warningIncidents, ...breachedIncidents];
  const mergedById = new Map();
  for (const incident of [...allSlaIncidents, ...suspiciousAccessIncidents]) {
    if (incident?.id) mergedById.set(incident.id, incident);
  }
  const allTrackedIncidents = [...mergedById.values()];
  const openPortIncidents = allTrackedIncidents.filter(isOpenPortIncident);
  const openPortIncidentRate = allTrackedIncidents.length > 0
    ? ((openPortIncidents.length / allTrackedIncidents.length) * 100)
    : 0;

  return (
    <div className="flex flex-col gap-6 h-full min-h-0">
      <div className="card p-4 border border-gray-800 bg-gray-900/70">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-gray-200 font-semibold">SLA Port-Open Report</p>
            <p className="text-xs text-gray-500 mt-1">Simple realtime percentage from incidents with open-port detection (rule 2).</p>
          </div>
          <button
            onClick={handleRefreshSystem}
            disabled={refreshingSystem}
            className="px-3 py-2 rounded-lg text-sm font-medium bg-cyan-700 hover:bg-cyan-600 text-white disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {refreshingSystem ? 'Refreshing…' : 'Refresh System'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
          <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-3">
            <p className="text-xs text-gray-500">SLA incidents</p>
            <p className="text-lg font-semibold text-gray-100">{allSlaIncidents.length}</p>
          </div>
          <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-3">
            <p className="text-xs text-gray-500">Open-port incidents</p>
            <p className="text-lg font-semibold text-cyan-300">{openPortIncidents.length}</p>
          </div>
          <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-3">
            <p className="text-xs text-gray-500">Suspicious access rate</p>
            <p className="text-lg font-semibold text-amber-300">{openPortIncidentRate.toFixed(2)}%</p>
          </div>
        </div>

        {lastCheckSummary && (
          <p className="text-xs text-gray-400 mt-3">
            Last check {new Date(lastCheckSummary.at).toLocaleString()} | Target {lastCheckSummary.targetIp} | Open {lastCheckSummary.openCount}/{lastCheckSummary.scanned} ({lastCheckSummary.openPercent.toFixed(2)}%) | Abnormal {lastCheckSummary.abnormalCount} ({lastCheckSummary.abnormalPercent.toFixed(2)}%)
          </p>
        )}
      </div>

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

      <div className="grid grid-cols-1 h-full min-h-0">
        <SlaLane
          title="Accès suspects détectés sur vos ports"
          incidents={suspiciousAccessIncidents}
          loading={loading}
          emptyLabel="Aucun accès suspect détecté par le contrôle des ports."
          onSelect={onSelect}
        />
      </div>
    </div>
  );
}