import React, { useState, useEffect } from 'react';
import { format } from 'date-fns';
import { fr } from 'date-fns/locale';
import { assignIncident, fetchAssignableUsers, fetchIncident, updateStatus, exportIncident, updateChecklist } from '../lib/api';
import ISOWorkflow from './ISOWorkflow';
import {
  CATEGORY_LABELS,
  NEXT_STATUS,
  NEXT_STATUS_LABEL,
  SEVERITY_LABELS,
  STATUS_LABELS,
  WORKFLOW_PHASE_LABELS,
  WORKFLOW_STATE_LABELS,
} from '../lib/constants';
import { X, Download, Shield, CheckSquare, Square, Clock3, Users, Route } from 'lucide-react';

function getSlaState(incident) {
  if (!incident.sla_due_at) {
    return { label: 'SLA automatique', className: 'sla-on-track' };
  }

  const dueAt = new Date(incident.sla_due_at);
  const warningAt = incident.sla_warning_at ? new Date(incident.sla_warning_at) : null;
  const now = new Date();

  if (incident.sla_breached_at || dueAt <= now) {
    return { label: 'SLA dépassé', className: 'sla-breached' };
  }

  if (warningAt && warningAt <= now) {
    return { label: 'SLA proche', className: 'sla-warning' };
  }

  return { label: 'SLA sous contrôle', className: 'sla-on-track' };
}

export default function IncidentDetail({ incidentId, onClose, onStatusChange }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [assigning, setAssigning] = useState(false);
  const [assignees, setAssignees] = useState([]);
  const [assigneesLoading, setAssigneesLoading] = useState(true);
  const [selectedAssigneeId, setSelectedAssigneeId] = useState('');

  const load = () => {
    setLoading(true);
    fetchIncident(incidentId)
      .then((payload) => {
        setData(payload);
        setSelectedAssigneeId(payload.incident.assigned_to || '');
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [incidentId]);

  useEffect(() => {
    setAssigneesLoading(true);
    fetchAssignableUsers()
      .then(({ users }) => setAssignees(users || []))
      .catch(console.error)
      .finally(() => setAssigneesLoading(false));
  }, []);

  const handleStatusChange = async () => {
    const next = NEXT_STATUS[data.incident.status];
    if (!next) return;
    setUpdating(true);
    try {
      await updateStatus(incidentId, next, null, null);
      onStatusChange?.(incidentId, next);
      load();
    } catch (e) {
      console.error(e);
    } finally {
      setUpdating(false);
    }
  };

  const handleAssign = async () => {
    setAssigning(true);
    try {
      const selectedUser = assignees.find((user) => user.id === selectedAssigneeId) || null;
      await assignIncident(incidentId, {
        assigned_to: selectedAssigneeId || null,
        note: selectedUser ? `Assignment updated to ${selectedUser.name}` : 'Assignment cleared',
      });
      onStatusChange?.(incidentId, data?.incident?.status);
      load();
    } catch (e) {
      console.error(e);
    } finally {
      setAssigning(false);
    }
  };

  const handleExport = async () => {
    setExportLoading(true);
    try {
      const exportData = await exportIncident(incidentId);
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `incident-loi18-07-${incidentId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error(e);
    } finally {
      setExportLoading(false);
    }
  };

  const handleChecklist = async (step, current) => {
    await updateChecklist(incidentId, step, !current);
    load();
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-gray-400">
      Chargement…
    </div>
  );

  if (!data) return null;

  const { incident, auditLogs, checklist, workflowEvents = [] } = data;
  const sev = SEVERITY_LABELS[incident.severity] || SEVERITY_LABELS.medium;
  const st  = STATUS_LABELS[incident.status] || STATUS_LABELS.open;
  const cat = CATEGORY_LABELS[incident.category] || { icon: '⚠️', label: incident.category };
  const nextStatus = NEXT_STATUS[incident.status];
  const nextLabel  = NEXT_STATUS_LABEL[incident.status];
  const checklistDone = checklist.filter(c => c.completed).length;
  const phase = WORKFLOW_PHASE_LABELS[incident.workflow_phase] || { label: incident.workflow_phase || 'Assess', className: 'phase-assess' };
  const workflowState = WORKFLOW_STATE_LABELS[incident.workflow_state] || { label: incident.workflow_state || 'Actif', className: 'status-open' };
  const slaState = getSlaState(incident);
  const selectedAssignee = assignees.find((user) => user.id === selectedAssigneeId) || null;

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-start justify-between p-6 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <span className="text-3xl">{cat.icon}</span>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={sev.className}>{sev.label}</span>
              <span className={st.className}>{st.label}</span>
            </div>
            <h2 className="text-gray-100 font-semibold">{incident.title}</h2>
            <p className="text-gray-500 text-xs mt-0.5 font-mono">{incident.id}</p>
          </div>
        </div>
        <button onClick={onClose} className="btn-ghost p-2">
          <X size={18} />
        </button>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">

        {/* Actions */}
        <div className="flex gap-3">
          {nextStatus && (
            <button
              onClick={handleStatusChange}
              disabled={updating}
              className="btn-primary flex items-center gap-2"
            >
              <Shield size={14} />
              {updating ? 'Mise à jour…' : nextLabel}
            </button>
          )}
          <button
            onClick={handleExport}
            disabled={exportLoading}
            className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium px-4 py-2 rounded-xl transition-colors"
          >
            <Download size={14} />
            {exportLoading ? 'Export…' : 'Export Loi 18-07'}
          </button>
        </div>

        {/* Info grid */}
        <div className="grid grid-cols-2 gap-4">
          {[
            ['Catégorie',    cat.label],
            ['Phase ISO',    phase.label],
            ['Workflow',     workflowState.label],
            ['Machine',      incident.machine_id || '—'],
            ['Adresse IP',   incident.ip_address || '—'],
            ['Reporter',     incident.anonymous ? 'Anonyme' : (incident.reporter_name || '—')],
            ['Département',  incident.department || '—'],
            ['Assigné à',    incident.assigned_user_name || incident.assigned_team || 'Non assigné'],
            ['Créé le',      format(new Date(incident.created_at), 'PPPp', { locale: fr })],
          ].map(([k, v]) => (
            <div key={k} className="bg-gray-800/50 rounded-xl p-3">
              <p className="text-gray-500 text-xs mb-0.5">{k}</p>
              <p className="text-gray-200 text-sm font-medium">{v}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="card p-4">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Route size={14} className="text-cyan-400" />
                <p className="text-gray-300 text-sm font-medium">Workflow ISO 27035</p>
              </div>
              <div className="flex items-center gap-2">
                <span className={workflowState.className}>{workflowState.label}</span>
                <span className={slaState.className}>{slaState.label}</span>
              </div>
            </div>
            <ISOWorkflow
              incidentId={incidentId}
              currentPhase={incident.workflow_phase}
              onTransition={() => { load(); onStatusChange?.(incidentId, data?.incident?.status); }}
            />
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">SLA courant</span>
                <span className="text-gray-200">
                  {incident.sla_due_at
                    ? format(new Date(incident.sla_due_at), 'PPPp', { locale: fr })
                    : 'Automatique'}
                </span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Dernière transition</span>
                <span className="text-gray-200">
                  {incident.last_transition_at
                    ? format(new Date(incident.last_transition_at), 'PPPp', { locale: fr })
                    : '—'}
                </span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Escalade</span>
                <span className="text-gray-200">Niveau {incident.escalation_level ?? 0}</span>
              </div>
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center gap-2 mb-3">
              <Users size={14} className="text-blue-400" />
              <p className="text-gray-300 text-sm font-medium">Assignation</p>
            </div>
            <label className="block text-gray-500 text-xs mb-2">Responsable IT</label>
            <div className="flex gap-2 items-start">
              <select
                value={selectedAssigneeId}
                onChange={(e) => setSelectedAssigneeId(e.target.value)}
                className="flex-1 bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-xl px-3 py-2 focus:outline-none focus:border-gray-500"
                disabled={assigneesLoading}
              >
                <option value="">File non assignée</option>
                {assignees.map((user) => (
                  <option key={user.id} value={user.id}>
                    {user.name} · {user.role} · {user.department || 'Sans département'}
                  </option>
                ))}
              </select>
              <button
                onClick={handleAssign}
                disabled={assigning || assigneesLoading}
                className="btn-primary whitespace-nowrap"
              >
                {assigning ? 'Assignation…' : 'Assigner'}
              </button>
            </div>
            <div className="mt-3 space-y-1 text-xs text-gray-500">
              <p>
                {assigneesLoading
                  ? 'Chargement de l’annuaire IT…'
                  : `${assignees.length} utilisateurs IT disponibles pour l’assignation.`}
              </p>
              {selectedAssignee && (
                <p>
                  Responsable supérieur: {selectedAssignee.manager_name || 'Non défini'}
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Description */}
        {incident.description && (
          <div className="card p-4">
            <p className="text-gray-400 text-xs mb-2">Description</p>
            <p className="text-gray-200 text-sm leading-relaxed">{incident.description}</p>
          </div>
        )}

        {/* Evidence hash */}
        <div className="card p-4">
          <div className="flex items-center gap-2 mb-2">
            <Shield size={14} className="text-green-400" />
            <p className="text-gray-300 text-sm font-medium">Intégrité — SHA-256</p>
          </div>
          <p className="text-green-400 font-mono text-xs break-all">{incident.evidence_hash}</p>
        </div>

        {/* Checklist */}
        {checklist.length > 0 && (
          <div className="card p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-gray-300 text-sm font-medium">Checklist de remédiation</p>
              <span className="text-gray-500 text-xs">{checklistDone}/{checklist.length}</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-1.5 mb-4">
              <div
                className="bg-green-500 h-1.5 rounded-full transition-all"
                style={{ width: `${checklist.length > 0 ? (checklistDone / checklist.length) * 100 : 0}%` }}
              />
            </div>
            <div className="space-y-2">
              {checklist.map((item) => (
                <button
                  key={item.step}
                  onClick={() => handleChecklist(item.step, item.completed)}
                  className="flex items-start gap-3 w-full text-left hover:bg-gray-800/50 rounded-lg p-2 transition-colors"
                >
                  {item.completed
                    ? <CheckSquare size={16} className="text-green-400 shrink-0 mt-0.5" />
                    : <Square size={16} className="text-gray-500 shrink-0 mt-0.5" />
                  }
                  <span className={`text-sm ${item.completed ? 'line-through text-gray-500' : 'text-gray-300'}`}>
                    {item.label}
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Clock3 size={14} className="text-cyan-400" />
            <p className="text-gray-300 text-sm font-medium">Timeline workflow</p>
          </div>
          <div className="space-y-3">
            {workflowEvents.map((event, i) => {
              const eventPhase = WORKFLOW_PHASE_LABELS[event.phase] || { label: event.phase, className: 'phase-assess' };

              return (
                <div key={event.id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-2 h-2 rounded-full bg-cyan-500 mt-1.5 shrink-0" />
                    {i < workflowEvents.length - 1 && <div className="w-px flex-1 bg-gray-700 mt-1" />}
                  </div>
                  <div className="pb-3 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={eventPhase.className}>{eventPhase.label}</span>
                      <span className="text-gray-200 text-xs font-medium">{event.event_type.replace('_', ' ')}</span>
                      {event.actor_name && <span className="text-gray-500 text-xs">par {event.actor_name}</span>}
                    </div>
                    {event.note && <p className="text-gray-400 text-xs mt-1">{event.note}</p>}
                    <div className="flex flex-wrap gap-x-3 gap-y-1 mt-1 text-gray-600 text-xs">
                      <span>{format(new Date(event.created_at), 'PPp', { locale: fr })}</span>
                      {event.due_at && <span>SLA: {format(new Date(event.due_at), 'PPp', { locale: fr })}</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Audit Trail */}
        <div className="card p-4">
          <p className="text-gray-300 text-sm font-medium mb-3">Piste d'audit (Loi 18-07)</p>
          <div className="space-y-3">
            {auditLogs.map((log, i) => (
              <div key={log.id} className="flex gap-3">
                <div className="flex flex-col items-center">
                  <div className="w-2 h-2 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                  {i < auditLogs.length - 1 && <div className="w-px flex-1 bg-gray-700 mt-1" />}
                </div>
                <div className="pb-3 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-gray-200 text-xs font-medium capitalize">{log.action.replace('_', ' ')}</span>
                    {log.actor_name && <span className="text-gray-500 text-xs">par {log.actor_name}</span>}
                    {log.old_value && log.new_value && (
                      <span className="text-gray-500 text-xs">{log.old_value} → {log.new_value}</span>
                    )}
                  </div>
                  <p className="text-gray-600 text-xs mt-0.5">
                    {format(new Date(log.created_at), 'PPp', { locale: fr })}
                  </p>
                  {log.log_hash && (
                    <p className="text-gray-700 font-mono text-xs mt-0.5 truncate">{log.log_hash.slice(0, 24)}…</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
