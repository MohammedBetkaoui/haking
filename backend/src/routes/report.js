const express = require('express');
const Joi = require('joi');
const pool = require('../db/pool');
const { hashIncident } = require('../utils/hash');
const { triage } = require('../utils/triage');
const { appendAuditLog } = require('../services/audit');
const { notifyIncidentEvent } = require('../services/notifications');
const {
  buildInitialIncidentState,
  buildInitialWorkflowEvents,
  appendWorkflowEvent,
} = require('../services/workflow');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

const reportSchema = Joi.object({
  category: Joi.string().valid('ransomware', 'phishing', 'device_loss', 'data_breach', 'suspicious_activity', 'other').required(),
  title: Joi.string().min(3).max(200).required(),
  description: Joi.string().max(2000).allow('', null),
  anonymous: Joi.boolean().default(false),
  user_id: Joi.string().uuid().allow(null),
  machine_id: Joi.string().max(200).allow('', null),
  metadata: Joi.object().default({}),
});

// POST /api/report
router.post('/', async (req, res) => {
  const { error, value } = reportSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const { severity, checklist } = triage(value.category);
    const incidentId = uuidv4();
    const now = new Date();
    const workflowState = buildInitialIncidentState({ severity, referenceAt: now });

    const evidenceHash = hashIncident({
      id: incidentId,
      timestamp: now.toISOString(),
      category: value.category,
      description: value.description,
    });

    await conn.query(
      `INSERT INTO incidents
         (id, user_id, anonymous, machine_id, ip_address, category, severity, title, description, status, source, workflow_phase, workflow_state, sla_due_at, sla_warning_at, sla_breached_at, escalation_level, last_transition_at, evidence_hash, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 'USER', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        incidentId,
        value.anonymous ? null : (value.user_id || null),
        value.anonymous ? 1 : 0,
        value.machine_id || null,
        ip,
        value.category,
        severity,
        value.title,
        value.description || null,
        workflowState.workflowPhase,
        workflowState.workflowState,
        workflowState.slaDueAt,
        workflowState.slaWarningAt,
        workflowState.slaBreachedAt,
        workflowState.escalationLevel,
        workflowState.lastTransitionAt,
        evidenceHash,
        JSON.stringify(value.metadata),
      ]
    );

    await appendAuditLog(conn, {
      incidentId,
      actorId: value.anonymous ? null : (value.user_id || null),
      actorRole: 'employee',
      action: 'created',
      newValue: { category: value.category, severity, workflow_phase: workflowState.workflowPhase },
      ipAddress: ip,
      createdAt: now,
    });

    const workflowEvents = buildInitialWorkflowEvents({
      incidentId,
      createdAt: now,
      severity,
    });

    for (const event of workflowEvents) {
      await appendWorkflowEvent(conn, event);
    }

    for (const item of checklist) {
      await conn.query(
        'INSERT INTO checklist_items (id, incident_id, step, label) VALUES (?, ?, ?, ?)',
        [uuidv4(), incidentId, item.step, item.label]
      );
    }

    await conn.commit();

    const io = req.app.get('io');
    if (io) {
      io.to('admins').emit('incident:new', {
        id: incidentId,
        title: value.title,
        category: value.category,
        severity,
        source: 'USER',
        ip_address: ip,
        status: 'open',
        workflow_phase: workflowState.workflowPhase,
        created_at: now.toISOString(),
        checklist,
      });
    }

    notifyIncidentEvent({
      eventType: 'incident_reported',
      incident: {
      id: incidentId,
      title: value.title,
      category: value.category,
      severity,
      status: 'open',
      workflow_phase: workflowState.workflowPhase,
      workflow_state: workflowState.workflowState,
      escalation_level: workflowState.escalationLevel,
      machine_id: value.machine_id || null,
      ip_address: ip,
      description: value.description || null,
      assigned_to: null,
      assigned_user_name: null,
      assigned_team: null,
    },
    }).catch((notifyErr) => {
      console.error('Notification error:', notifyErr);
    });

    return res.status(201).json({
      success: true,
      incident_id: incidentId,
      severity,
      evidence_hash: evidenceHash,
      workflow_phase: workflowState.workflowPhase,
      sla_due_at: workflowState.slaDueAt,
      checklist,
    });
  } catch (err) {
    await conn.rollback();
    console.error('Report error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    conn.release();
  }
});

module.exports = router;
