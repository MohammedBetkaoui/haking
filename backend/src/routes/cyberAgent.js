const express = require('express');
const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

const MAX_REPORTS = 200;
const reports = [];

const embeddedEventSchema = Joi.object({
  event_id: Joi.string().max(120).required(),
  timestamp: Joi.date().iso().required(),
  event_type: Joi.string().max(120).required(),
  incident_type: Joi.string().max(120).allow('', null),
  source_ip: Joi.string().ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' }).allow(null),
  dest_ip: Joi.string().ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' }).allow(null),
  severity: Joi.string().max(32).allow('', null),
  risk_score: Joi.number().integer().min(0).max(100).required(),
  details: Joi.object().unknown(true).default({}),
});

const reportSchema = Joi.object({
  agent: Joi.string().max(100).default('CyberSentinel'),
  event_id: Joi.string().max(120).allow('', null),
  incident_id: Joi.string().max(120).allow('', null),
  timestamp: Joi.date().iso().optional(),
  classification: Joi.string().valid('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').required(),
  risk_score: Joi.number().integer().min(0).max(100).required(),
  confidence: Joi.string().valid('LOW', 'MEDIUM', 'HIGH').allow(null),
  event_type: Joi.string().max(120).required(),
  source_ip: Joi.string().ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' }).allow(null),
  source_ips: Joi.array().items(Joi.string().ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' })).default([]),
  dest_ip: Joi.string().ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' }).allow(null),
  narrative: Joi.string().max(4000).allow('', null),
  summary: Joi.string().max(4000).allow('', null),
  impact: Joi.string().max(2000).allow('', null),
  rca: Joi.string().max(2000).allow('', null),
  security_weaknesses: Joi.array().items(Joi.string().max(500)).default([]),
  recommendations: Joi.array().items(Joi.string().max(500)).default([]),
  timeline: Joi.array().items(Joi.string().max(1000)).default([]),
  events: Joi.array().items(embeddedEventSchema).default([]),
  agent_status: Joi.string().valid('running', 'idle', 'error').default('running'),
  tags: Joi.array().items(Joi.string().max(80)).default([]),
  mitre_techniques: Joi.array().items(
    Joi.object({
      id: Joi.string().max(40).required(),
      name: Joi.string().max(200).required(),
      tactic: Joi.string().max(120).allow('', null),
    })
  ).default([]),
  kill_chain_stage: Joi.string().max(160).allow('', null),
  root_causes: Joi.array().items(Joi.string().max(500)).default([]),
  immediate_actions: Joi.array().items(Joi.string().max(500)).default([]),
  short_term_fixes: Joi.array().items(Joi.string().max(500)).default([]),
  strategic_controls: Joi.array().items(Joi.string().max(500)).default([]),
  patterns: Joi.array().items(
    Joi.object({
      name: Joi.string().max(200).required(),
      severity: Joi.string().max(40).allow('', null),
      description: Joi.string().max(500).allow('', null),
    })
  ).default([]),
});

function buildRiskOptimization(report) {
  const actions = [
    ...(report.immediate_actions || []).slice(0, 2),
    ...(report.short_term_fixes || []).slice(0, 2),
    ...(report.strategic_controls || []).slice(0, 2),
  ];

  return {
    score: report.risk_score,
    classification: report.classification,
    priority: report.risk_score >= 81 ? 'P1' : report.risk_score >= 61 ? 'P2' : report.risk_score >= 31 ? 'P3' : 'P4',
    optimization_actions: actions,
  };
}

function storeReport(value, req) {
  const receivedAt = new Date().toISOString();
  const report = {
    id: uuidv4(),
    agent: value.agent,
    event_id: value.event_id || null,
    incident_id: value.incident_id || null,
    timestamp: value.timestamp ? new Date(value.timestamp).toISOString() : receivedAt,
    received_at: receivedAt,
    classification: value.classification,
    risk_score: value.risk_score,
    confidence: value.confidence || null,
    event_type: value.event_type,
    incident_type: value.incident_type || null,
    source_ip: value.source_ip || null,
    source_ips: value.source_ips || (value.source_ip ? [value.source_ip] : []),
    dest_ip: value.dest_ip || null,
    narrative: value.narrative || '',
    summary: value.summary || value.narrative || '',
    impact: value.impact || '',
    rca: value.rca || '',
    recommendations: value.recommendations || [],
    timeline: value.timeline || [],
    events: value.events || [],
    agent_status: value.agent_status || 'running',
    tags: value.tags,
    mitre_techniques: value.mitre_techniques,
    kill_chain_stage: value.kill_chain_stage || null,
    root_causes: value.root_causes,
    immediate_actions: value.immediate_actions,
    short_term_fixes: value.short_term_fixes,
    strategic_controls: value.strategic_controls,
    patterns: value.patterns,
    security_weaknesses: value.security_weaknesses || [],
    risk_optimization: buildRiskOptimization(value),
  };

  reports.unshift(report);
  if (reports.length > MAX_REPORTS) {
    reports.splice(MAX_REPORTS);
  }

  const io = req.app.get('io');
  if (io) {
    io.to('admins').emit('cyberagent:report', report);
    io.to('admins').emit('cyberagent:incident', report);
  }

  return report;
}

router.get('/reports', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
    return res.json({ reports: reports.slice(0, limit) });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to list cyber agent reports' });
  }
});

router.get('/incidents', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
    return res.json({ incidents: reports.slice(0, limit) });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to list cyber agent incidents' });
  }
});

router.post('/reports', async (req, res) => {
  const { error, value } = reportSchema.validate(req.body, {
    abortEarly: false,
    stripUnknown: true,
  });

  if (error) {
    return res.status(400).json({
      error: 'Invalid report payload',
      details: error.details.map((d) => d.message),
    });
  }

  try {
    const report = storeReport(value, req);

    return res.status(201).json({ success: true, report });
  } catch (submitError) {
    console.error('Cyber agent report error:', submitError);
    return res.status(500).json({ error: 'Unable to persist cyber agent report' });
  }
});

router.post('/incidents', async (req, res) => {
  const { error, value } = reportSchema.validate(req.body, {
    abortEarly: false,
    stripUnknown: true,
  });

  if (error) {
    return res.status(400).json({
      error: 'Invalid incident payload',
      details: error.details.map((d) => d.message),
    });
  }

  try {
    const report = storeReport(value, req);
    return res.status(201).json({ success: true, incident: report });
  } catch (submitError) {
    console.error('Cyber agent incident error:', submitError);
    return res.status(500).json({ error: 'Unable to persist cyber agent incident' });
  }
});

router.delete('/reports/:id', async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ error: 'Report ID is required' });
    }

    const reportIndex = reports.findIndex((r) => r.id === id);

    if (reportIndex === -1) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const deletedReport = reports.splice(reportIndex, 1)[0];

    console.log(`[CyberAgent] Report deleted: ${id}`);

    const io = req.app.get('io');
    if (io) {
      io.to('admins').emit('cyberagent:report-deleted', { id, deletedAt: new Date().toISOString() });
    }

    return res.status(200).json({ success: true, message: 'Report deleted permanently', report: deletedReport });
  } catch (error) {
    console.error('Cyber agent report delete error:', error);
    return res.status(500).json({ error: 'Unable to delete cyber agent report' });
  }
});

module.exports = router;
