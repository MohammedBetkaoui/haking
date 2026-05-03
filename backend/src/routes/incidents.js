const express = require('express');
const pool = require('../db/pool');
const { appendAuditLog } = require('../services/audit');
const { appendWorkflowEvent, resolveStatusTransition, computeSlaWindow } = require('../services/workflow');
const { getAssignableUserById } = require('../services/users');

const router = express.Router();

function buildUpdateStatement(fields) {
  const entries = Object.entries(fields).filter(([, value]) => value !== undefined);

  return {
    setClause: entries.map(([column]) => `${column} = ?`).join(', '),
    values: entries.map(([, value]) => value),
  };
}

// GET /api/incidents
router.get('/', async (req, res) => {
  try {
    const { status, category, severity, assigned_to, workflow_state, limit = 50, offset = 0 } = req.query;
    const conditions = [];
    const params = [];

    if (status)   { conditions.push('i.status = ?');   params.push(status); }
    if (category) { conditions.push('i.category = ?'); params.push(category); }
    if (severity) { conditions.push('i.severity = ?'); params.push(severity); }
    if (assigned_to) { conditions.push('i.assigned_to = ?'); params.push(assigned_to); }
    if (workflow_state) { conditions.push('i.workflow_state = ?'); params.push(workflow_state); }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const [rows] = await pool.query(
      `SELECT i.*,
              u.name AS reporter_name,
              u.department AS reporter_department,
        assignee.name AS assigned_user_name,
        assignee.role AS assigned_user_role,
        assignee.department AS assigned_user_department,
              (SELECT COUNT(*) FROM checklist_items ci WHERE ci.incident_id = i.id AND ci.completed = 1) AS checklist_done,
              (SELECT COUNT(*) FROM checklist_items ci WHERE ci.incident_id = i.id) AS checklist_total
       FROM incidents i
       LEFT JOIN users u ON u.id = i.user_id
      LEFT JOIN users assignee ON assignee.id = i.assigned_to
       ${where}
       ORDER BY i.created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, parseInt(limit), parseInt(offset)]
    );

    const [countRows] = await pool.query(
      `SELECT COUNT(*) AS total FROM incidents i ${where}`,
      params
    );

    return res.json({ incidents: rows, total: countRows[0].total });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/incidents/stats
router.get('/stats', async (req, res) => {
  try {
    const [[counts], [byCategory], [bySeverity], [recentTTR]] = await Promise.all([
      pool.query('SELECT status, COUNT(*) AS count FROM incidents GROUP BY status'),
      pool.query('SELECT category, COUNT(*) AS count FROM incidents GROUP BY category ORDER BY count DESC'),
      pool.query('SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity'),
      pool.query(`
        SELECT
          AVG(TIMESTAMPDIFF(MINUTE, created_at, updated_at)) AS avg_minutes,
          DATE(created_at) AS day
        FROM incidents
        WHERE status = 'closed' AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY day ORDER BY day
      `),
    ]);

    return res.json({
      byStatus:   counts,
      byCategory,
      bySeverity,
      timeToReport: recentTTR,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/incidents/:id
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const [incident] = await pool.query(
      `SELECT i.*, u.name AS reporter_name, u.email AS reporter_email, u.department,
              assignee.name AS assigned_user_name,
              assignee.role AS assigned_user_role,
              assignee.department AS assigned_user_department
       FROM incidents i
       LEFT JOIN users u ON u.id = i.user_id
       LEFT JOIN users assignee ON assignee.id = i.assigned_to
       WHERE i.id = ?`,
      [id]
    );
    if (!incident.length) return res.status(404).json({ error: 'Not found' });

    const [[auditLogs], [checklist], [workflowEvents]] = await Promise.all([
      pool.query(
        `SELECT al.*, u.name AS actor_name FROM audit_logs al
         LEFT JOIN users u ON u.id = al.actor_id
         WHERE al.incident_id = ? ORDER BY al.created_at ASC`,
        [id]
      ),
      pool.query(
        'SELECT * FROM checklist_items WHERE incident_id = ? ORDER BY step ASC',
        [id]
      ),
      pool.query(
        `SELECT we.*, u.name AS actor_name FROM workflow_events we
         LEFT JOIN users u ON u.id = we.actor_id
         WHERE we.incident_id = ? ORDER BY we.created_at ASC`,
        [id]
      ),
    ]);

    return res.json({
      incident: incident[0],
      auditLogs,
      checklist,
      workflowEvents,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH /api/incidents/:id/status
router.patch('/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status, note, actor_id } = req.body;
  const validStatuses = ['open', 'in_progress', 'mitigating', 'closed'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const [incidentRes] = await conn.query('SELECT * FROM incidents WHERE id = ? FOR UPDATE', [id]);
    if (!incidentRes.length) {
      await conn.rollback();
      return res.status(404).json({ error: 'Not found' });
    }
    const incident = incidentRes[0];
    const oldStatus = incident.status;
    const transition = resolveStatusTransition(incident, status, new Date());
    const { setClause, values } = buildUpdateStatement(transition.incidentUpdate);

    await conn.query(`UPDATE incidents SET ${setClause} WHERE id = ?`, [...values, id]);

    for (const event of transition.workflowEvents) {
      await appendWorkflowEvent(conn, {
        incidentId: id,
        actorId: actor_id || null,
        actorRole: event.actorRole || 'it',
        phase: event.phase,
        eventType: event.eventType,
        fromState: event.fromState,
        toState: event.toState,
        note: note || event.note,
        dueAt: event.dueAt,
        warningAt: event.warningAt,
        breachedAt: event.breachedAt,
        escalationLevel: event.escalationLevel,
      });
    }

    await appendAuditLog(conn, {
      incidentId: id,
      actorId: actor_id || null,
      actorRole: 'it',
      action: 'status_changed',
      oldValue: oldStatus,
      newValue: status,
      note: note || null,
      ipAddress: ip,
    });

    await conn.commit();

    const io = req.app.get('io');
    if (io) io.to('admins').emit('incident:updated', {
      id,
      status,
      oldStatus,
      workflow_phase: transition.incidentUpdate.workflow_phase || incident.workflow_phase,
      sla_due_at: transition.incidentUpdate.sla_due_at || incident.sla_due_at,
    });

    return res.json({ success: true, id, status });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    conn.release();
  }
});

// PATCH /api/incidents/:id/assignment
router.patch('/:id/assignment', async (req, res) => {
  const { id } = req.params;
  const { assigned_to, assigned_team, actor_id, note } = req.body;
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const [incidentRes] = await conn.query('SELECT * FROM incidents WHERE id = ? FOR UPDATE', [id]);
    if (!incidentRes.length) {
      await conn.rollback();
      return res.status(404).json({ error: 'Not found' });
    }

    const incident = incidentRes[0];
    const updatedAt = new Date();
    let assignee = null;

    if (assigned_to) {
      assignee = await getAssignableUserById(conn, assigned_to);
      if (!assignee) {
        await conn.rollback();
        return res.status(400).json({ error: 'Assigned user is not available in the IT directory' });
      }
    }

    const resolvedAssignedTeam = assigned_team || assignee?.department || null;
    await conn.query(
      'UPDATE incidents SET assigned_to = ?, assigned_team = ?, last_transition_at = ? WHERE id = ?',
      [assigned_to || null, resolvedAssignedTeam, updatedAt, id]
    );

    await appendWorkflowEvent(conn, {
      incidentId: id,
      actorId: actor_id || null,
      actorRole: 'it',
      phase: incident.workflow_phase || 'assess',
      eventType: 'assigned',
      fromState: incident.workflow_state || 'active',
      toState: incident.workflow_state || 'active',
      note: note || (assignee ? `Incident assigned to ${assignee.name}.` : 'Incident assignment cleared.'),
      escalationLevel: incident.escalation_level || 0,
      createdAt: updatedAt,
    });

    await appendAuditLog(conn, {
      incidentId: id,
      actorId: actor_id || null,
      actorRole: 'it',
      action: 'assignment_changed',
      oldValue: JSON.stringify({ assigned_to: incident.assigned_to, assigned_team: incident.assigned_team }),
      newValue: {
        assigned_to: assigned_to || null,
        assigned_team: resolvedAssignedTeam,
        assigned_user_name: assignee?.name || null,
        assigned_user_role: assignee?.role || null,
      },
      note: note || null,
      ipAddress: ip,
      createdAt: updatedAt,
    });

    await conn.commit();

    const io = req.app.get('io');
    if (io) io.to('admins').emit('incident:updated', {
      id,
      assigned_to: assigned_to || null,
      assigned_team: resolvedAssignedTeam,
      assigned_user_name: assignee?.name || null,
      assigned_user_role: assignee?.role || null,
    });

    return res.json({
      success: true,
      id,
      assigned_to: assigned_to || null,
      assigned_team: resolvedAssignedTeam,
      assigned_user_name: assignee?.name || null,
      assigned_user_role: assignee?.role || null,
    });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    conn.release();
  }
});

// PUT /api/incidents/:id/phase — ISO 27035 manual phase transition
router.put('/:id/phase', async (req, res) => {
  const { id } = req.params;
  const { toPhase, comment, actor_id } = req.body;

  const PHASES = ['detect', 'report', 'assess', 'respond', 'learn'];
  if (!PHASES.includes(toPhase)) {
    return res.status(400).json({ error: 'Phase invalide' });
  }
  if (!comment || !comment.trim()) {
    return res.status(400).json({ error: 'Un commentaire est obligatoire pour les transitions de phase' });
  }

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const [rows] = await conn.query('SELECT * FROM incidents WHERE id = ? FOR UPDATE', [id]);
    if (!rows.length) {
      await conn.rollback();
      return res.status(404).json({ error: 'Not found' });
    }
    const incident = rows[0];
    const fromPhase = incident.workflow_phase || 'assess';
    const fromIdx = PHASES.indexOf(fromPhase);
    const toIdx = PHASES.indexOf(toPhase);

    if (toIdx <= fromIdx) {
      await conn.rollback();
      return res.status(400).json({ error: 'Impossible de revenir à une phase précédente' });
    }

    const now = new Date();
    const slaWindow = computeSlaWindow(toPhase, incident.severity, now);

    const updateFields = {
      workflow_phase: toPhase,
      last_transition_at: now,
    };

    if (toPhase === 'respond' && ['open', 'in_progress'].includes(incident.status)) {
      updateFields.status = 'mitigating';
    } else if (toPhase === 'learn') {
      updateFields.status = 'closed';
      updateFields.resolved_at = incident.resolved_at || now;
      updateFields.closed_at = now;
      updateFields.learned_at = now;
      updateFields.sla_due_at = null;
      updateFields.sla_warning_at = null;
      updateFields.sla_breached_at = null;
    }

    if (toPhase !== 'learn' && slaWindow.dueAt) {
      updateFields.sla_due_at = slaWindow.dueAt;
      updateFields.sla_warning_at = slaWindow.warningAt;
      updateFields.sla_breached_at = null;
      updateFields.workflow_state = 'active';
    }

    const { setClause, values } = buildUpdateStatement(updateFields);
    await conn.query(`UPDATE incidents SET ${setClause} WHERE id = ?`, [...values, id]);

    await appendWorkflowEvent(conn, {
      incidentId: id,
      actorId: actor_id || null,
      actorRole: actor_id ? 'it' : 'system',
      phase: toPhase,
      eventType: 'manual_phase_transition',
      fromState: fromPhase,
      toState: toPhase,
      note: comment.trim(),
      dueAt: slaWindow.dueAt,
      warningAt: slaWindow.warningAt,
      createdAt: now,
    });

    await appendAuditLog(conn, {
      incidentId: id,
      actorId: actor_id || null,
      actorRole: actor_id ? 'it' : 'system',
      action: 'phase_transition',
      oldValue: fromPhase,
      newValue: toPhase,
      note: comment.trim(),
      ipAddress: ip,
      createdAt: now,
    });

    await conn.commit();

    const io = req.app.get('io');
    if (io) io.to('admins').emit('incident:updated', {
      id,
      workflow_phase: toPhase,
      status: updateFields.status || incident.status,
      sla_due_at: updateFields.sla_due_at !== undefined ? updateFields.sla_due_at : incident.sla_due_at,
    });

    return res.json({ success: true, id, fromPhase, toPhase });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    conn.release();
  }
});

// PATCH /api/incidents/:id/checklist/:step
router.patch('/:id/checklist/:step', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const { id, step } = req.params;
    const { completed, actor_id } = req.body;
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;

    await conn.beginTransaction();

    const [rows] = await conn.query(
      `SELECT ci.*, i.workflow_phase, i.workflow_state, i.escalation_level
         FROM checklist_items ci
         JOIN incidents i ON i.id = ci.incident_id
        WHERE ci.incident_id = ? AND ci.step = ?
        FOR UPDATE`,
      [id, parseInt(step)]
    );

    if (!rows.length) {
      await conn.rollback();
      return res.status(404).json({ error: 'Checklist item not found' });
    }

    const item = rows[0];
    await conn.query(
      'UPDATE checklist_items SET completed = ?, completed_at = ? WHERE incident_id = ? AND step = ?',
      [completed ? 1 : 0, completed ? new Date() : null, id, parseInt(step)]
    );

    await appendAuditLog(conn, {
      incidentId: id,
      actorId: actor_id || null,
      actorRole: 'it',
      action: 'checklist_updated',
      oldValue: JSON.stringify({ step: item.step, completed: Boolean(item.completed) }),
      newValue: { step: item.step, completed: Boolean(completed), label: item.label },
      note: item.label,
      ipAddress: ip,
    });

    await appendWorkflowEvent(conn, {
      incidentId: id,
      actorId: actor_id || null,
      actorRole: 'it',
      phase: item.workflow_phase || 'assess',
      eventType: 'checklist_updated',
      fromState: item.workflow_state || 'active',
      toState: item.workflow_state || 'active',
      note: `${item.label} -> ${completed ? 'completed' : 'reopened'}`,
      escalationLevel: item.escalation_level || 0,
    });

    await conn.commit();
    return res.json({ success: true });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    conn.release();
  }
});

// GET /api/incidents/:id/export
router.get('/:id/export', async (req, res) => {
  try {
    const { id } = req.params;
    const [[incidentRows], [auditRows], [checklistRows]] = await Promise.all([
      pool.query(
        `SELECT i.*, u.name AS reporter_name, u.email AS reporter_email, u.department
         FROM incidents i LEFT JOIN users u ON u.id = i.user_id WHERE i.id = ?`,
        [id]
      ),
      pool.query(
        `SELECT al.*, u.name AS actor_name FROM audit_logs al
         LEFT JOIN users u ON u.id = al.actor_id WHERE al.incident_id = ? ORDER BY al.created_at ASC`,
        [id]
      ),
      pool.query('SELECT * FROM checklist_items WHERE incident_id = ? ORDER BY step ASC', [id]),
    ]);

    if (!incidentRows.length) return res.status(404).json({ error: 'Not found' });

    const exportData = {
      export_version: '1.0',
      standard: "Loi 18-07 — Protection des données personnelles (Algérie)",
      exported_at: new Date().toISOString(),
      incident: incidentRows[0],
      audit_trail: auditRows,
      remediation_checklist: checklistRows,
      integrity: {
        evidence_hash: incidentRows[0].evidence_hash,
        audit_chain_length: auditRows.length,
        last_log_hash: auditRows[auditRows.length - 1]?.log_hash || null,
      },
    };

    const conn = await pool.getConnection();

    try {
      await appendAuditLog(conn, {
        incidentId: id,
        actorRole: 'dpo',
        action: 'exported',
        newValue: { exported_at: exportData.exported_at },
        ipAddress: req.socket.remoteAddress,
      });
    } finally {
      conn.release();
    }

    return res.json(exportData);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
