const pool = require('../db/pool');
const { appendAuditLog } = require('../services/audit');
const { appendWorkflowEvent } = require('../services/workflow');
const { notifyIncidentEvent } = require('../services/notifications');
const { resolveEscalationTarget } = require('../services/users');

/**
 * @typedef {{
 *   id: string,
 *   status?: string,
 *   workflow_phase?: string,
 *   workflow_state?: string,
 *   sla_due_at?: Date | string | null,
 *   sla_warning_at?: Date | string | null,
 *   sla_breached_at?: Date | string | null,
 *   escalation_level?: number,
 *   assigned_to?: string | null,
 *   assigned_team?: string | null,
 *   assigned_user_name?: string | null,
 *   assigned_user_role?: string | null,
 *   machine_id?: string | null,
 *   ip_address?: string | null,
 *   title?: string,
 *   category?: string,
 *   severity?: string,
 *   description?: string | null,
 * }} IncidentLike
 */

/**
 * @typedef {{
 *   to: (room: string) => { emit: (event: string, payload: unknown) => void }
 * }} IoLike
 */

/**
 * @param {IoLike | undefined} io
 * @param {Record<string, unknown>} payload
 */
async function emitIncidentUpdate(io, payload) {
  if (io) {
    io.to('admins').emit('incident:updated', payload);
  }
}

/**
 * @param {IncidentLike} incident
 * @param {IoLike | undefined} io
 */
async function markWarning(incident, io) {
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const [rowsResult] = await conn.query('SELECT * FROM incidents WHERE id = ? FOR UPDATE', [incident.id]);
    const rows = /** @type {IncidentLike[]} */ (rowsResult);
    const current = rows[0];
    if (!current || current.status === 'closed' || current.workflow_state !== 'active') {
      await conn.rollback();
      return false;
    }

    const now = new Date();
    await conn.query(
      'UPDATE incidents SET workflow_state = ?, last_transition_at = ? WHERE id = ?',
      ['warning', now, current.id]
    );

    await appendWorkflowEvent(conn, {
      incidentId: current.id,
      actorRole: 'system',
      phase: current.workflow_phase,
      eventType: 'sla_warning',
      fromState: 'active',
      toState: 'warning',
      note: `SLA warning triggered for ${current.workflow_phase} phase.`,
      dueAt: current.sla_due_at,
      warningAt: current.sla_warning_at,
      escalationLevel: current.escalation_level,
      createdAt: now,
    });

    await appendAuditLog(conn, {
      incidentId: current.id,
      actorRole: 'system',
      action: 'sla_warning',
      newValue: {
        workflow_phase: current.workflow_phase,
        workflow_state: 'warning',
        sla_due_at: current.sla_due_at,
      },
      note: `SLA warning triggered for ${current.workflow_phase}`,
      createdAt: now,
    });

    await conn.commit();
    await emitIncidentUpdate(io, {
      id: current.id,
      workflow_state: 'warning',
      sla_due_at: current.sla_due_at,
    });
    return true;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/**
 * @param {IncidentLike} incident
 * @param {IoLike | undefined} io
 */
async function markBreach(incident, io) {
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const [rowsResult] = await conn.query(
      `SELECT i.*, assignee.name AS assigned_user_name, assignee.role AS assigned_user_role
         FROM incidents i
         LEFT JOIN users assignee ON assignee.id = i.assigned_to
        WHERE i.id = ?
        FOR UPDATE`,
      [incident.id]
    );
    const rows = /** @type {IncidentLike[]} */ (rowsResult);
    const current = rows[0];
    if (!current || current.status === 'closed' || current.sla_breached_at) {
      await conn.rollback();
      return false;
    }

    const now = new Date();
    const escalationTarget = await resolveEscalationTarget(/** @type {any} */ (conn), current.assigned_to || null);
    const nextEscalationLevel = Number(current.escalation_level || 0) + 1;
    const nextAssignedTo = escalationTarget?.id || current.assigned_to || null;
    const nextAssignedTeam = escalationTarget?.department || current.assigned_team || null;

    await conn.query(
      `UPDATE incidents
          SET workflow_state = ?,
              sla_breached_at = ?,
              escalation_level = ?,
              assigned_to = ?,
              assigned_team = ?,
              last_transition_at = ?
        WHERE id = ?`,
      ['breached', now, nextEscalationLevel, nextAssignedTo, nextAssignedTeam, now, current.id]
    );

    await appendWorkflowEvent(conn, {
      incidentId: current.id,
      actorRole: 'system',
      phase: current.workflow_phase,
      eventType: 'escalated',
      fromState: current.workflow_state,
      toState: 'breached',
      note: escalationTarget
        ? `SLA breached. Escalated to ${escalationTarget.name}.`
        : 'SLA breached. No superior assignee available; escalation level raised.',
      dueAt: current.sla_due_at,
      warningAt: current.sla_warning_at,
      breachedAt: now,
      escalationLevel: nextEscalationLevel,
      createdAt: now,
    });

    await appendAuditLog(conn, {
      incidentId: current.id,
      actorRole: 'system',
      action: 'sla_breached',
      oldValue: JSON.stringify({
        assigned_to: current.assigned_to,
        escalation_level: current.escalation_level,
        workflow_state: current.workflow_state,
      }),
      newValue: {
        assigned_to: nextAssignedTo,
        assigned_team: nextAssignedTeam,
        escalation_level: nextEscalationLevel,
        workflow_state: 'breached',
        workflow_phase: current.workflow_phase,
      },
      note: escalationTarget
        ? `Escalated automatically to ${escalationTarget.name}`
        : 'Escalated automatically without reassignment target',
      createdAt: now,
    });

    await conn.commit();

    await notifyIncidentEvent({
      eventType: 'incident_escalated',
      incident: {
        id: current.id,
        title: current.title,
        category: current.category,
        severity: current.severity,
        status: current.status,
        workflow_phase: current.workflow_phase,
        workflow_state: 'breached',
        escalation_level: nextEscalationLevel,
        machine_id: current.machine_id,
        ip_address: current.ip_address,
        assigned_to: nextAssignedTo,
        assigned_team: nextAssignedTeam,
        assigned_user_name: escalationTarget?.name || current.assigned_user_name,
        description: current.description,
        note: escalationTarget
          ? `Automatic escalation to ${escalationTarget.name} (${escalationTarget.role}).`
          : 'Automatic escalation triggered; no higher assignee found.',
      },
    });

    await emitIncidentUpdate(io, {
      id: current.id,
      workflow_state: 'breached',
      sla_breached_at: now,
      escalation_level: nextEscalationLevel,
      assigned_to: nextAssignedTo,
      assigned_team: nextAssignedTeam,
      assigned_user_name: escalationTarget?.name || null,
      assigned_user_role: escalationTarget?.role || null,
    });

    return true;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/**
 * @param {{ io?: IoLike }} [options]
 */
async function runSlaMonitor({ io } = {}) {
  const now = new Date();
  const [warningRowsResult] = await pool.query(
    `SELECT id, workflow_phase, sla_due_at, sla_warning_at, escalation_level
       FROM incidents
      WHERE status <> 'closed'
        AND workflow_state = 'active'
        AND sla_warning_at IS NOT NULL
        AND sla_warning_at <= ?
        AND (sla_due_at IS NULL OR sla_due_at > ?)
      ORDER BY sla_warning_at ASC`,
    [now, now]
  );
  const [breachRowsResult] = await pool.query(
    `SELECT id
       FROM incidents
      WHERE status <> 'closed'
        AND sla_due_at IS NOT NULL
        AND sla_due_at <= ?
        AND sla_breached_at IS NULL
      ORDER BY sla_due_at ASC`,
    [now]
  );

  const warningRows = /** @type {IncidentLike[]} */ (warningRowsResult);
  const breachRows = /** @type {IncidentLike[]} */ (breachRowsResult);

  // Process warnings and breaches fully in parallel for minimum latency.
  const [warningResults, breachResults] = await Promise.all([
    Promise.all(warningRows.map((incident) => markWarning(incident, io).catch(() => false))),
    Promise.all(breachRows.map((incident) => markBreach(incident, io).catch(() => false))),
  ]);

  const warnings = warningResults.filter(Boolean).length;
  const breaches = breachResults.filter(Boolean).length;

  return { warnings, breaches, processedAt: now.toISOString() };
}

module.exports = { runSlaMonitor };