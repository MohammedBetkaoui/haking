import React from 'react';
import { formatDistanceToNow } from 'date-fns';
import { fr } from 'date-fns/locale';
import { CATEGORY_LABELS, SEVERITY_LABELS, STATUS_LABELS, WORKFLOW_PHASE_LABELS } from '../lib/constants';

function getSlaPresentation(incident) {
  if (!incident.sla_due_at) {
    return null;
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

  return {
    label: `SLA ${formatDistanceToNow(dueAt, { addSuffix: true, locale: fr })}`,
    className: 'sla-on-track',
  };
}

const SEV_LEFT_BORDER = {
  critical: 'border-l-red-500',
  high:     'border-l-orange-500',
  medium:   'border-l-yellow-500',
  low:      'border-l-green-500',
};

export default function IncidentCard({ incident, onClick, isNew = false }) {
  const sev = SEVERITY_LABELS[incident.severity] || SEVERITY_LABELS.medium;
  const st  = STATUS_LABELS[incident.status]   || STATUS_LABELS.open;
  const cat = CATEGORY_LABELS[incident.category] || { icon: '⚠️', label: incident.category };
  const phase = WORKFLOW_PHASE_LABELS[incident.workflow_phase] || { label: incident.workflow_phase || 'Assess', className: 'phase-assess' };
  const sla = getSlaPresentation(incident);
  const leftBorder = SEV_LEFT_BORDER[incident.severity] || 'border-l-gray-600';

  return (
    <button
      onClick={() => onClick(incident)}
      className={`card w-full text-left p-4 border-l-2 ${leftBorder} hover:border-gray-600 hover:bg-gray-800/40 hover:-translate-y-px active:translate-y-0 transition-all duration-150 ${
        isNew ? 'ring-1 ring-blue-500/40 shadow-blue-900/20 shadow-lg' : ''
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <span className="text-xl shrink-0 leading-none mt-0.5">{cat.icon}</span>
          <div className="min-w-0 flex-1">
            <p className="text-gray-100 text-sm font-semibold truncate leading-snug">{incident.title}</p>
            <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
              <span className={sev.className}>{sev.label}</span>
              <span className={st.className}>{st.label}</span>
              <span className={phase.className}>{phase.label}</span>
              {sla && <span className={sla.className}>{sla.label}</span>}
              {isNew && (
                <span className="bg-blue-500/20 text-blue-400 border border-blue-500/30 text-xs px-2 py-0.5 rounded-full animate-pulse">
                  Nouveau
                </span>
              )}
            </div>
            <p className="text-gray-500 text-xs mt-1.5 truncate">
              {cat.label}
              {incident.reporter_name && !incident.anonymous && ` · ${incident.reporter_name}`}
              {incident.machine_id && ` · 💻 ${incident.machine_id}`}
              {(incident.assigned_user_name || incident.assigned_team) && ` · 👤 ${incident.assigned_user_name || incident.assigned_team}`}
            </p>
          </div>
        </div>
        <div className="text-right shrink-0 ml-1">
          <p className="text-gray-500 text-xs whitespace-nowrap">
            {formatDistanceToNow(new Date(incident.created_at), { addSuffix: true, locale: fr })}
          </p>
          {incident.ip_address && (
            <p className="text-gray-600 text-[11px] mt-0.5 font-mono">{incident.ip_address}</p>
          )}
        </div>
      </div>
    </button>
  );
}
