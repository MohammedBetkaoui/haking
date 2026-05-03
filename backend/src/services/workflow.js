const { v4: uuidv4 } = require('uuid');

const ISO27035_PHASES = ['detect', 'report', 'assess', 'respond', 'learn'];

const PHASE_SLA_MINUTES = {
  detect: { default: 0 },
  report: { default: 0 },
  assess: { default: 5 },
  respond: { critical: 15, high: 30, medium: 60, low: 120, default: 120 },
  learn: { default: 48 * 60 },
};

function addMinutes(referenceAt, minutes) {
  return new Date(referenceAt.getTime() + (minutes * 60 * 1000));
}

function getPhaseSlaMinutes(phase, severity) {
  const phaseConfig = PHASE_SLA_MINUTES[phase] || {};
  return phaseConfig[severity] ?? phaseConfig.default ?? null;
}

function computeSlaWindow(phase, severity, referenceAt = new Date()) {
  const minutes = getPhaseSlaMinutes(phase, severity);
  if (!minutes || minutes <= 0) {
    return { minutes, dueAt: null, warningAt: null };
  }

  const warningOffset = minutes <= 5
    ? Math.max(1, minutes - 1)
    : Math.max(1, Math.floor(minutes * 0.8));

  return {
    minutes,
    dueAt: addMinutes(referenceAt, minutes),
    warningAt: addMinutes(referenceAt, warningOffset),
  };
}

function buildInitialIncidentState({ severity, referenceAt = new Date() }) {
  const assessWindow = computeSlaWindow('assess', severity, referenceAt);

  return {
    workflowPhase: 'assess',
    workflowState: 'active',
    escalationLevel: 0,
    slaDueAt: assessWindow.dueAt,
    slaWarningAt: assessWindow.warningAt,
    slaBreachedAt: null,
    lastTransitionAt: referenceAt,
  };
}

function buildInitialWorkflowEvents({ incidentId, createdAt = new Date(), severity }) {
  const assessWindow = computeSlaWindow('assess', severity, createdAt);

  return [
    {
      incidentId,
      phase: 'detect',
      eventType: 'phase_completed',
      actorRole: 'system',
      fromState: null,
      toState: 'completed',
      note: 'Incident detected and captured from desktop intake.',
      createdAt,
    },
    {
      incidentId,
      phase: 'report',
      eventType: 'phase_completed',
      actorRole: 'system',
      fromState: 'queued',
      toState: 'completed',
      note: 'Incident report stored and triaged automatically.',
      createdAt,
    },
    {
      incidentId,
      phase: 'assess',
      eventType: 'phase_started',
      actorRole: 'system',
      fromState: null,
      toState: 'active',
      note: 'Initial ISO 27035 assessment phase started.',
      dueAt: assessWindow.dueAt,
      warningAt: assessWindow.warningAt,
      escalationLevel: 0,
      createdAt,
    },
  ];
}

async function appendWorkflowEvent(conn, {
  incidentId,
  phase,
  eventType,
  actorId = null,
  actorRole = null,
  fromState = null,
  toState = null,
  note = null,
  dueAt = null,
  warningAt = null,
  breachedAt = null,
  escalationLevel = 0,
  createdAt = new Date(),
}) {
  const eventId = uuidv4();
  const eventTimestamp = createdAt instanceof Date ? createdAt : new Date(createdAt);

  await conn.query(
    `INSERT INTO workflow_events
       (id, incident_id, phase, event_type, actor_id, actor_role, from_state, to_state, note, due_at, warning_at, breached_at, escalation_level, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      eventId,
      incidentId,
      phase,
      eventType,
      actorId,
      actorRole,
      fromState,
      toState,
      note,
      dueAt,
      warningAt,
      breachedAt,
      escalationLevel,
      eventTimestamp,
    ]
  );

  return { id: eventId, createdAt: eventTimestamp };
}

function resolveStatusTransition(incident, nextStatus, referenceAt = new Date()) {
  if (nextStatus === 'in_progress') {
    return {
      incidentUpdate: {
        status: 'in_progress',
        workflow_state: 'active',
        acknowledged_at: incident.acknowledged_at || referenceAt,
        last_transition_at: referenceAt,
      },
      workflowEvents: [
        {
          phase: incident.workflow_phase || 'assess',
          eventType: 'acknowledged',
          actorRole: 'it',
          fromState: 'active',
          toState: 'active',
          note: 'Incident acknowledged by the IT team.',
        },
      ],
    };
  }

  if (nextStatus === 'mitigating') {
    const respondWindow = computeSlaWindow('respond', incident.severity, referenceAt);

    return {
      incidentUpdate: {
        status: 'mitigating',
        workflow_phase: 'respond',
        workflow_state: 'active',
        acknowledged_at: incident.acknowledged_at || referenceAt,
        sla_due_at: respondWindow.dueAt,
        sla_warning_at: respondWindow.warningAt,
        sla_breached_at: null,
        last_transition_at: referenceAt,
      },
      workflowEvents: [
        {
          phase: 'assess',
          eventType: 'phase_completed',
          actorRole: 'it',
          fromState: 'active',
          toState: 'completed',
          note: 'Assessment completed, response actions started.',
        },
        {
          phase: 'respond',
          eventType: 'phase_started',
          actorRole: 'it',
          fromState: null,
          toState: 'active',
          note: 'Response phase started.',
          dueAt: respondWindow.dueAt,
          warningAt: respondWindow.warningAt,
          escalationLevel: incident.escalation_level || 0,
        },
      ],
    };
  }

  if (nextStatus === 'closed') {
    return {
      incidentUpdate: {
        status: 'closed',
        workflow_phase: 'learn',
        workflow_state: 'completed',
        sla_due_at: null,
        sla_warning_at: null,
        sla_breached_at: null,
        last_transition_at: referenceAt,
        resolved_at: incident.resolved_at || referenceAt,
        closed_at: referenceAt,
        learned_at: referenceAt,
      },
      workflowEvents: [
        {
          phase: incident.workflow_phase || 'respond',
          eventType: 'phase_completed',
          actorRole: 'it',
          fromState: 'active',
          toState: 'completed',
          note: 'Operational response completed.',
        },
        {
          phase: 'learn',
          eventType: 'phase_completed',
          actorRole: 'it',
          fromState: 'active',
          toState: 'completed',
          note: 'Post-incident learning captured at closure.',
        },
      ],
    };
  }

  throw new Error(`Unsupported status transition: ${nextStatus}`);
}

module.exports = {
  ISO27035_PHASES,
  computeSlaWindow,
  buildInitialIncidentState,
  buildInitialWorkflowEvents,
  appendWorkflowEvent,
  resolveStatusTransition,
};