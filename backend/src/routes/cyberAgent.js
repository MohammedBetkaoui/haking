const express = require('express');
const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');
const { sendCyberAgentEmailAlert } = require('../services/notifications');

const router = express.Router();

const MAX_REPORTS = 200;
const reports = [];
const REPORT_TRIGGER_SEVERITIES = new Set(['MEDIUM', 'HIGH', 'CRITICAL']);

const NETWORK_INTRUSION_PATTERNS = [
  /port\s*scan/i,
  /brute[-\s]?force/i,
  /failed\s+login/i,
  /lateral\s+movement/i,
  /command\s+and\s+control|\bc2\b/i,
  /unauthorized\s+access/i,
  /exploit/i,
  /reconnaissance/i,
  /reverse\s+shell/i,
  /suspicious\s+traffic/i,
];

const MALWARE_RANSOMWARE_PATTERNS = [
  /ransomware/i,
  /encrypt(?:ion|ed|ing)?\s+files?/i,
  /ransom\s+note/i,
  /crypto[-\s]?locker/i,
  /trojan|worm|backdoor|rootkit/i,
  /malicious\s+binary|payload\s+execution/i,
  /known\s+malware\s+hash/i,
  /mass\s+file\s+rename/i,
  /shadow\s+copy\s+delet(?:e|ion)/i,
];

const ATTACK_VECTOR_HINTS = [
  { re: /phishing|email/i, label: 'Phishing-delivered payload' },
  { re: /rdp|remote\s+desktop/i, label: 'RDP abuse' },
  { re: /ssh/i, label: 'SSH brute-force or credential abuse' },
  { re: /smb/i, label: 'SMB lateral movement' },
  { re: /web\s+exploit|sql\s+injection|xss/i, label: 'Web exploitation' },
  { re: /powershell|wmi/i, label: 'Living-off-the-land execution' },
];

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/gi;
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const HASH_REGEX = /\b[a-fA-F0-9]{64}\b/g;
const USER_REGEX = /\b(?:user(?:name)?|account)\s*[:=]\s*([a-zA-Z0-9._-]{2,})\b/gi;
const HOSTNAME_REGEX = /\b(?:host(?:name)?|machine)\s*[:=]\s*([a-zA-Z0-9._-]{2,})\b/gi;

const monitorSchema = Joi.object({
  source: Joi.string().max(120).allow('', null),
  timestamp: Joi.date().iso().optional(),
  event: Joi.alternatives().try(Joi.object().unknown(true), Joi.string().max(20000)),
  events: Joi.array().items(Joi.alternatives().try(Joi.object().unknown(true), Joi.string().max(20000))).max(200),
  logs: Joi.alternatives().try(Joi.string().max(40000), Joi.array().items(Joi.string().max(20000)).max(200)),
  telemetry: Joi.object().unknown(true),
  alert: Joi.object().unknown(true),
})
  .or('event', 'events', 'logs', 'telemetry', 'alert')
  .unknown(true);

function normalizeSeverity(raw) {
  const value = String(raw || '').trim().toUpperCase();
  if (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(value)) return value;

  const numeric = Number(raw);
  if (Number.isFinite(numeric)) {
    if (numeric >= 9) return 'CRITICAL';
    if (numeric >= 7) return 'HIGH';
    if (numeric >= 4) return 'MEDIUM';
    return 'LOW';
  }

  return null;
}

function severityFromScore(score) {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

function severityRank(level) {
  return { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[String(level || 'LOW').toUpperCase()] || 1;
}

function buildIncidentId(now = new Date()) {
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  const suffix = String(Math.floor(Math.random() * 10000)).padStart(4, '0');
  return `INC-${yyyy}${mm}${dd}-${suffix}`;
}

function collectNormalizedEvents(payload) {
  const events = [];

  if (Array.isArray(payload.events)) events.push(...payload.events);
  if (payload.event) events.push(payload.event);
  if (payload.alert) events.push(payload.alert);
  if (payload.telemetry) events.push(payload.telemetry);

  if (typeof payload.logs === 'string') {
    events.push({ message: payload.logs });
  } else if (Array.isArray(payload.logs)) {
    for (const line of payload.logs) events.push({ message: line });
  }

  return events.map((item, idx) => {
    if (typeof item === 'string') {
      return { id: `event-${idx + 1}`, message: item, raw: item };
    }

    const candidate = item || {};
    const primaryText = [
      candidate.message,
      candidate.description,
      candidate.summary,
      candidate.alert,
      candidate.log,
      candidate.event_type,
      candidate.title,
    ].find(Boolean);

    return {
      id: String(candidate.event_id || candidate.id || `event-${idx + 1}`),
      message: primaryText ? String(primaryText) : JSON.stringify(candidate),
      severity: candidate.severity || candidate.risk || null,
      source_ip: candidate.source_ip || candidate.src_ip || null,
      dest_ip: candidate.dest_ip || candidate.destination_ip || null,
      hostname: candidate.hostname || candidate.host || candidate.machine || null,
      user: candidate.user || candidate.username || candidate.account || null,
      raw: candidate,
    };
  });
}

function unique(list) {
  return Array.from(new Set(list.filter(Boolean)));
}

function scoreMatches(text, patterns) {
  let hits = 0;
  for (const re of patterns) {
    if (re.test(text)) hits += 1;
  }
  return hits;
}

function extractRegexValues(text, regex, groupIndex = 0) {
  const values = [];
  const re = new RegExp(regex.source, regex.flags);
  let match;
  while ((match = re.exec(text)) !== null) {
    values.push(match[groupIndex] || match[0]);
    if (match.index === re.lastIndex) re.lastIndex += 1;
  }
  return values;
}

function buildAttackVector(textBlob) {
  for (const hint of ATTACK_VECTOR_HINTS) {
    if (hint.re.test(textBlob)) return hint.label;
  }
  return 'Pattern suggests active intrusion or malware execution';
}

function determineThreatType(networkScore, malwareScore) {
  if (networkScore <= 0 && malwareScore <= 0) return null;
  return malwareScore > networkScore ? 'Malware / ransomware' : 'Network intrusion';
}

function createStructuredIncidentReport({ severity, threatType, events, evidence, score }) {
  const now = new Date();
  const incidentId = buildIncidentId(now);

  return {
    incident_id: incidentId,
    timestamp: now.toISOString(),
    severity,
    threat_type: threatType,
    affected_assets: {
      ips: evidence.ips,
      hostnames: evidence.hostnames,
      user_accounts: evidence.users,
    },
    attack_vector_method: evidence.attackVector,
    evidence_summary: {
      score,
      event_count: events.length,
      iocs: {
        ips: evidence.ips,
        hashes: evidence.hashes,
        cves: evidence.cves,
      },
      log_snippets: evidence.snippets,
    },
    recommended_immediate_actions: threatType === 'Malware / ransomware'
      ? [
          'Isolate impacted hosts from the network immediately.',
          'Block known malicious hashes and indicators at endpoint and gateway layers.',
          'Preserve forensic artifacts before any cleanup actions.',
        ]
      : [
          'Block or rate-limit suspicious source IPs at perimeter controls.',
          'Force credential reset for potentially impacted user accounts.',
          'Capture volatile evidence from affected hosts and network devices.',
        ],
    cve_references: evidence.cves,
    output_channels: ['Email alert'],
  };
}

function buildEmailBody(report) {
  return [
    `Incident ID: ${report.incident_id}`,
    `Timestamp (UTC): ${report.timestamp}`,
    `Severity: ${report.severity}`,
    `Threat type: ${report.threat_type}`,
    `Affected assets (IPs): ${report.affected_assets.ips.join(', ') || 'none'}`,
    `Affected assets (hostnames): ${report.affected_assets.hostnames.join(', ') || 'none'}`,
    `Affected assets (users): ${report.affected_assets.user_accounts.join(', ') || 'none'}`,
    `Attack vector / method: ${report.attack_vector_method}`,
    `Evidence snippets:`,
    ...report.evidence_summary.log_snippets.map((s, i) => `  ${i + 1}. ${s}`),
    `IoCs (hashes): ${report.evidence_summary.iocs.hashes.join(', ') || 'none'}`,
    `CVE references: ${report.cve_references.join(', ') || 'none'}`,
    `Recommended immediate actions:`,
    ...report.recommended_immediate_actions.map((a, i) => `  ${i + 1}. ${a}`),
  ].join('\n');
}

function storeGeneratedThreatReport(report, req, score) {
  const stored = {
    id: uuidv4(),
    agent: 'CyberSentinel',
    incident_id: report.incident_id,
    timestamp: report.timestamp,
    received_at: new Date().toISOString(),
    classification: report.severity,
    risk_score: score,
    event_type: report.threat_type,
    source_ips: report.affected_assets.ips,
    source_ip: report.affected_assets.ips[0] || null,
    dest_ip: null,
    summary: `${report.threat_type} detected with ${report.severity} severity`,
    narrative: report.attack_vector_method,
    recommendations: report.recommended_immediate_actions,
    tags: ['automated-detection', 'threat-report'],
    structured_report: report,
  };

  reports.unshift(stored);
  if (reports.length > MAX_REPORTS) {
    reports.splice(MAX_REPORTS);
  }

  const io = req.app.get('io');
  if (io) {
    io.to('admins').emit('cyberagent:report', stored);
    io.to('admins').emit('cyberagent:incident', stored);
  }

  return stored;
}

async function analyzeIncomingSecurityEvents(payload, req) {
  const events = collectNormalizedEvents(payload);
  if (events.length === 0) {
    return {
      status: 'SUSPICIOUS',
      reason: 'No parsable security events found in payload',
      required_data: ['logs', 'alerts', 'network telemetry'],
    };
  }

  const ips = [];
  const hostnames = [];
  const users = [];
  const hashes = [];
  const cves = [];
  const snippets = [];
  const incomingSeverities = [];

  let networkScore = 0;
  let malwareScore = 0;

  for (const event of events) {
    const text = String(event.message || '').slice(0, 5000);
    const rawText = JSON.stringify(event.raw || {}).slice(0, 5000);
    const blob = `${text}\n${rawText}`;

    networkScore += scoreMatches(blob, NETWORK_INTRUSION_PATTERNS) * 14;
    malwareScore += scoreMatches(blob, MALWARE_RANSOMWARE_PATTERNS) * 18;

    ips.push(...extractRegexValues(blob, IPV4_REGEX));
    hashes.push(...extractRegexValues(blob, HASH_REGEX));
    cves.push(...extractRegexValues(blob, CVE_REGEX));
    users.push(...extractRegexValues(blob, USER_REGEX, 1));
    hostnames.push(...extractRegexValues(blob, HOSTNAME_REGEX, 1));

    if (event.source_ip) ips.push(event.source_ip);
    if (event.dest_ip) ips.push(event.dest_ip);
    if (event.hostname) hostnames.push(event.hostname);
    if (event.user) users.push(event.user);

    const normalizedIncomingSeverity = normalizeSeverity(event.severity);
    if (normalizedIncomingSeverity) incomingSeverities.push(normalizedIncomingSeverity);

    snippets.push(text.slice(0, 280));
  }

  const score = Math.min(100, Math.max(networkScore, malwareScore));
  const detectedSeverity = severityFromScore(score);
  const strongestIncomingSeverity = incomingSeverities.sort((a, b) => severityRank(b) - severityRank(a))[0] || 'LOW';
  const severity = severityRank(strongestIncomingSeverity) > severityRank(detectedSeverity)
    ? strongestIncomingSeverity
    : detectedSeverity;

  const threatType = determineThreatType(networkScore, malwareScore);
  const evidence = {
    ips: unique(ips),
    hostnames: unique(hostnames),
    users: unique(users),
    hashes: unique(hashes),
    cves: unique(cves),
    snippets: unique(snippets).slice(0, 5),
    attackVector: buildAttackVector(snippets.join(' ')),
  };

  // Require at least two independent indicators to avoid noisy false positives.
  const indicatorCount = [
    threatType ? 1 : 0,
    evidence.ips.length > 0 ? 1 : 0,
    evidence.hashes.length > 0 ? 1 : 0,
    evidence.snippets.length > 0 ? 1 : 0,
    evidence.cves.length > 0 ? 1 : 0,
  ].reduce((sum, n) => sum + n, 0);

  if (!threatType || score < 40 || indicatorCount < 2) {
    return {
      status: 'SUSPICIOUS',
      reason: 'Evidence is insufficient to confirm network intrusion or malware/ransomware threat',
      required_data: [
        'Additional log lines around the event window',
        'Endpoint process and file-hash telemetry',
        'Network flow metadata (src/dst, ports, protocol)',
      ],
      observed_indicators: {
        score,
        ips: evidence.ips,
        hashes: evidence.hashes,
        cves: evidence.cves,
      },
    };
  }

  if (!REPORT_TRIGGER_SEVERITIES.has(severity)) {
    return {
      status: 'THREAT_DETECTED_LOW',
      severity,
      threat_type: threatType,
      score,
      message: 'Threat detected but below reporting threshold (MEDIUM+).',
    };
  }

  const report = createStructuredIncidentReport({
    severity,
    threatType,
    events,
    evidence,
    score,
  });

  const emailResult = await sendCyberAgentEmailAlert({
    subject: `[Guardian CyberAgent] ${report.severity} ${report.threat_type} - ${report.incident_id}`,
    text: buildEmailBody(report),
  });

  const stored = storeGeneratedThreatReport(report, req, score);

  return {
    status: 'REPORTED',
    report,
    output: {
      channel: 'email_alert',
      delivery: emailResult,
    },
    stored_id: stored.id,
  };
}

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

router.post('/monitor', async (req, res) => {
  const { error, value } = monitorSchema.validate(req.body, {
    abortEarly: false,
    stripUnknown: true,
  });

  if (error) {
    return res.status(400).json({
      error: 'Invalid monitoring payload',
      details: error.details.map((d) => d.message),
    });
  }

  try {
    const analysis = await analyzeIncomingSecurityEvents(value, req);
    return res.status(200).json(analysis);
  } catch (analyzeError) {
    console.error('Cyber agent monitor error:', analyzeError);
    return res.status(500).json({ error: 'Unable to analyze incoming security events' });
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
