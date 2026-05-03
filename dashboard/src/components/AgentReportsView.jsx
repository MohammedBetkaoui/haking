import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Bot, Loader2, Shield, ActivitySquare, Trash2 } from 'lucide-react';
import { fetchCyberAgentIncidents, deleteCyberAgentReport } from '../lib/api';
import { connectSocket } from '../lib/socket';

const CLASS_STYLES = {
  CRITICAL: 'text-red-300 border-red-500/30 bg-red-500/10',
  HIGH: 'text-orange-300 border-orange-500/30 bg-orange-500/10',
  MEDIUM: 'text-yellow-300 border-yellow-500/30 bg-yellow-500/10',
  LOW: 'text-green-300 border-green-500/30 bg-green-500/10',
};

const STATUS_STYLE = {
  running: 'text-green-300 border-green-500/30 bg-green-500/10',
  idle: 'text-yellow-300 border-yellow-500/30 bg-yellow-500/10',
  error: 'text-red-300 border-red-500/30 bg-red-500/10',
};

function getAgentStatus(lastUpdate, explicitStatus) {
  if (explicitStatus === 'error') return 'error';
  if (!lastUpdate) return explicitStatus || 'idle';

  const ageMs = Date.now() - new Date(lastUpdate).getTime();
  if (ageMs <= 90 * 1000) return 'running';
  return 'idle';
}

function scoreStyle(score) {
  if (score >= 81) return 'bg-red-500';
  if (score >= 61) return 'bg-orange-500';
  if (score >= 31) return 'bg-yellow-500';
  return 'bg-green-500';
}

function IncidentRow({ incident, selected, onSelect, onDelete, deleting }) {
  const score = Number(incident?.risk_score || 0);
  const severityClass = CLASS_STYLES[incident.classification] || CLASS_STYLES.MEDIUM;

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(incident.id)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(incident.id);
        }
      }}
      className={`w-full card border p-3 text-left transition-all ${
        selected ? 'border-cyan-500/50 bg-cyan-500/10' : 'border-gray-800/80 hover:border-gray-700'
      }`}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`px-2 py-0.5 text-xs rounded-full border font-semibold ${severityClass}`}>
          {incident.classification}
        </span>
        <span className="text-xs px-2 py-0.5 rounded-full border border-gray-700 bg-gray-800 text-gray-300">
          {incident.incident_id || incident.event_id}
        </span>
        <span className="ml-auto text-xs text-gray-500">
          {new Date(incident.timestamp || incident.received_at).toLocaleString('fr-FR')}
        </span>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onDelete(incident.id);
          }}
          disabled={deleting}
          title="Delete report"
          className="ml-1 inline-flex items-center justify-center p-1.5 rounded-md border border-red-500/30 text-red-300 hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Trash2 size={14} />
        </button>
      </div>
      <p className="text-sm text-gray-300 mt-2 line-clamp-2">{incident.summary || incident.narrative || 'No summary provided.'}</p>
      <div className="mt-2 h-1.5 rounded-full bg-gray-800 overflow-hidden">
        <div className={`h-full ${scoreStyle(score)}`} style={{ width: `${Math.max(4, Math.min(100, score))}%` }} />
      </div>
      <div className="mt-2 text-xs text-gray-500">
        Risk {score}% · {incident.source_ips?.join(', ') || incident.source_ip || 'n/a'}
      </div>
    </div>
  );
}

function IncidentDetails({ incident }) {
  if (!incident) {
    return <div className="card border border-gray-800 p-6 text-gray-500">Select an incident to see details.</div>;
  }

  return (
    <section className="card border border-gray-800 p-4 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <span className={`px-2 py-0.5 text-xs rounded-full border font-semibold ${CLASS_STYLES[incident.classification] || CLASS_STYLES.MEDIUM}`}>
          {incident.classification}
        </span>
        <span className="text-sm text-gray-300 font-semibold">{incident.incident_id || incident.event_id}</span>
        <span className="ml-auto text-gray-500 text-xs">{new Date(incident.timestamp || incident.received_at).toLocaleString('fr-FR')}</span>
      </div>

      <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3">
        <div className="text-xs text-gray-500">Summary</div>
        <p className="text-sm text-gray-200 mt-1">{incident.summary || incident.narrative || 'No summary available.'}</p>
      </div>

      <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3">
        <div className="text-xs text-gray-500 mb-2">Root Cause Analysis</div>
        <p className="text-sm text-gray-200">{incident.rca || incident.root_causes?.[0] || 'No RCA provided.'}</p>
        {incident.security_weaknesses?.length > 0 && (
          <ul className="mt-2 text-xs text-gray-400 space-y-1 list-disc list-inside">
            {incident.security_weaknesses.map((w, idx) => <li key={`${incident.id}-weak-${idx}`}>{w}</li>)}
          </ul>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3">
          <div className="text-xs text-gray-500 mb-2">Timeline</div>
          {incident.timeline?.length > 0 ? (
            <ol className="text-xs text-gray-300 space-y-1 list-decimal list-inside">
              {incident.timeline.map((t, idx) => <li key={`${incident.id}-tl-${idx}`}>{t}</li>)}
            </ol>
          ) : (
            <div className="text-xs text-gray-500">No timeline available.</div>
          )}
        </div>

        <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3">
          <div className="text-xs text-gray-500 mb-2">Recommendations</div>
          {incident.recommendations?.length > 0 ? (
            <ul className="text-xs text-gray-300 space-y-1 list-disc list-inside">
              {incident.recommendations.map((r, idx) => <li key={`${incident.id}-rec-${idx}`}>{r}</li>)}
            </ul>
          ) : (
            <div className="text-xs text-gray-500">No recommendations available.</div>
          )}
        </div>
      </div>

      <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3 text-xs text-gray-400">
        Impact: <span className="text-gray-300">{incident.impact || 'Potential operational/security impact under investigation.'}</span>
      </div>
    </section>
  );
}

export default function AgentReportsView() {
  const [loading, setLoading] = useState(true);
  const [reports, setReports] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [lastAgentUpdate, setLastAgentUpdate] = useState(null);
  const [explicitAgentStatus, setExplicitAgentStatus] = useState('idle');
  const [deletingId, setDeletingId] = useState(null);

  const handleDeleteReport = async (id) => {
    if (!id || deletingId) return;

    setDeletingId(id);
    try {
      await deleteCyberAgentReport(id);
      setReports((prev) => prev.filter((r) => r.id !== id));
      setSelectedId((current) => (current === id ? null : current));
    } catch (error) {
      console.error('Failed to delete report:', error);
    } finally {
      setDeletingId(null);
    }
  };

  useEffect(() => {
    let mounted = true;
    fetchCyberAgentIncidents(50)
      .then((data) => {
        if (mounted) {
          const incidents = data?.incidents || data?.reports || [];
          setReports(incidents);
          setSelectedId((current) => current || incidents[0]?.id || null);
          if (incidents[0]?.timestamp || incidents[0]?.received_at) {
            setLastAgentUpdate(incidents[0].timestamp || incidents[0].received_at);
          }
        }
      })
      .catch(() => {
        if (mounted) {
          setReports([]);
        }
      })
      .finally(() => {
        if (mounted) {
          setLoading(false);
        }
      });

    const s = connectSocket();
    const onIncident = (report) => {
      setExplicitAgentStatus(report.agent_status || 'running');
      setLastAgentUpdate(report.timestamp || report.received_at || new Date().toISOString());
      setReports((prev) => [report, ...prev].slice(0, 100));
      setSelectedId((current) => current || report.id);
    };
    const onDeleted = ({ id }) => {
      setReports((prev) => prev.filter((r) => r.id !== id));
      setSelectedId((current) => (current === id ? null : current));
    };

    s.on('cyberagent:incident', onIncident);
    s.on('cyberagent:report', onIncident);
    s.on('cyberagent:report-deleted', onDeleted);
    s.on('connect_error', () => setExplicitAgentStatus('error'));

    const statusTimer = setInterval(() => {
      setExplicitAgentStatus((curr) => (curr === 'error' ? 'error' : curr));
    }, 5000);

    return () => {
      clearInterval(statusTimer);
      mounted = false;
      s.off('cyberagent:incident', onIncident);
      s.off('cyberagent:report', onIncident);
      s.off('cyberagent:report-deleted', onDeleted);
      s.off('connect_error');
    };
  }, []);

  const selectedIncident = useMemo(
    () => reports.find((r) => r.id === selectedId) || null,
    [reports, selectedId]
  );

  const criticalCount = useMemo(() => reports.filter((r) => r.classification === 'CRITICAL').length, [reports]);
  const highCount = useMemo(() => reports.filter((r) => r.classification === 'HIGH').length, [reports]);
  const agentStatus = getAgentStatus(lastAgentUpdate, explicitAgentStatus);

  if (loading) {
    return (
      <div className="card py-16 flex flex-col items-center gap-3 text-gray-500">
        <Loader2 size={26} className="animate-spin text-cyan-400" />
        Loading SOC incidents...
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5 pb-8">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card border border-cyan-500/20 bg-cyan-500/5 p-4">
          <div className="text-xs text-cyan-300 flex items-center gap-2"><Bot size={14} /> Incident Feed</div>
          <div className="text-2xl text-gray-100 font-bold mt-2">{reports.length}</div>
          <div className="text-xs text-gray-500 mt-1">Grouped incidents</div>
        </div>
        <div className="card border border-red-500/20 bg-red-500/5 p-4">
          <div className="text-xs text-red-300 flex items-center gap-2"><AlertTriangle size={14} /> Critical</div>
          <div className="text-2xl text-gray-100 font-bold mt-2">{criticalCount}</div>
          <div className="text-xs text-gray-500 mt-1">Immediate response</div>
        </div>
        <div className="card border border-orange-500/20 bg-orange-500/5 p-4">
          <div className="text-xs text-orange-300 flex items-center gap-2"><Shield size={14} /> High Risk</div>
          <div className="text-2xl text-gray-100 font-bold mt-2">{highCount}</div>
          <div className="text-xs text-gray-500 mt-1">Continuous monitoring</div>
        </div>
        <div className="card border border-gray-800 bg-gray-900/60 p-4">
          <div className="text-xs text-gray-400 flex items-center gap-2"><ActivitySquare size={14} /> AI Agent Status</div>
          <div className={`mt-2 inline-flex px-2.5 py-1 rounded-full border text-xs font-semibold ${STATUS_STYLE[agentStatus] || STATUS_STYLE.idle}`}>
            {agentStatus.toUpperCase()}
          </div>
          <div className="text-xs text-gray-500 mt-2">
            Last update: {lastAgentUpdate ? new Date(lastAgentUpdate).toLocaleTimeString('fr-FR') : 'n/a'}
          </div>
        </div>
      </div>

      {reports.length === 0 ? (
        <div className="card py-16 text-center text-gray-500">No cyber-agent incidents yet.</div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[380px_1fr] gap-4">
          <div className="space-y-3 max-h-[75vh] overflow-auto pr-1">
            {reports.map((report) => (
              <IncidentRow
                key={report.id}
                incident={report}
                selected={selectedId === report.id}
                onSelect={setSelectedId}
                onDelete={handleDeleteReport}
                deleting={deletingId === report.id}
              />
            ))}
          </div>
          <IncidentDetails incident={selectedIncident} />
        </div>
      )}
    </div>
  );
}
