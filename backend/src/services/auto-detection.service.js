'use strict';

/**
 * auto-detection.service.js
 * ─────────────────────────
 * Automated incident generation from three independent sources:
 *
 *  1. SYSTEM_SCANNER — TCP network sweep that flags unknown devices
 *  2. LOG_WATCHER    — Platform log reader (Windows Security events / Linux auth.log)
 *  3. SIEM           — Authenticated POST webhook for external SIEM alerts
 *
 * All three converge on the single createIncident() function which runs
 * the full ISO 27035 workflow (detect → report → assess) identically to
 * a human submission from the Electron desktop app.
 *
 * Source values stored in incidents.source:
 *   'USER'            Human submission via desktop intake
 *   'SYSTEM_SCANNER'  Network scanner auto-detection
 *   'LOG_WATCHER'     System log watcher
 *   'SIEM'            External SIEM webhook
 *
 * Env vars (all optional):
 *   AUTO_DETECT_DEDUP_WINDOW_MS   Deduplication window in ms  (default: 600000)
 *   AUTO_DETECT_SCANNER_ENABLED   'true' to start scanner     (default: false)
 *   AUTO_DETECT_LOG_WATCHER_ENABLED 'true' to start log watcher (default: false)
 *   SCANNER_INTERVAL_MS           setInterval delay in ms for fast scanning (default: 30000 = 30 s)
 *                                 Set to 0 to disable and fall back to SCANNER_CRON.
 *   SCANNER_CRON                  Cron for scanner (used only when SCANNER_INTERVAL_MS=0, default: every 5 min)
 *   SCANNER_SUBNETS               Comma-separated CIDRs       (default: 192.168.1.0/24)
 *   SCANNER_TRUSTED_IPS           Comma-separated IPs to skip
 *   SCANNER_PROBE_PORT            TCP port to probe           (default: 80)
 *   SCANNER_PROBE_TIMEOUT_MS      Probe timeout               (default: 800)
 *   LOG_WATCHER_CRON              Cron for log watcher        (default: every minute)
 *   LOG_WATCHER_FILE              Linux log file              (default: /var/log/auth.log)
 *   SIEM_WEBHOOK_SECRET           Required API key for /api/auto-detect/siem
 */

const crypto = require('crypto');
const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const net = require('net');
const os = require('os');

const cron = require('node-cron');
const express = require('express');
const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');

const pool = require('../db/pool');
const { hashIncident } = require('../utils/hash');
const { triage } = require('../utils/triage');
const { appendAuditLog } = require('./audit');
const { notifyIncidentEvent } = require('./notifications');
const {
  buildInitialIncidentState,
  buildInitialWorkflowEvents,
  appendWorkflowEvent,
} = require('./workflow');

const execAsync = promisify(exec);

/** @typedef {'USER'|'SYSTEM_SCANNER'|'LOG_WATCHER'|'SIEM'} IncidentSource */

const VALID_SOURCES = ['USER', 'SYSTEM_SCANNER', 'LOG_WATCHER', 'SIEM', 'SYSTEM'];
const VALID_CATEGORIES = ['ransomware', 'phishing', 'device_loss', 'data_breach', 'suspicious_activity', 'other'];

// ─── Deduplication ───────────────────────────────────────────────────────────
// Prevents the same automated finding from creating multiple incidents within
// the dedup window (default 10 minutes).

const DEDUP_WINDOW_MS = parseInt(process.env.AUTO_DETECT_DEDUP_WINDOW_MS || '600000', 10);

/** @type {Map<string, number>} fingerprint → expiry timestamp */
const recentFingerprints = new Map();

function isDuplicate(fingerprint) {
  const expiry = recentFingerprints.get(fingerprint);
  if (expiry && Date.now() < expiry) return true;
  recentFingerprints.set(fingerprint, Date.now() + DEDUP_WINDOW_MS);
  // Prune stale entries to avoid unbounded memory growth
  if (recentFingerprints.size > 2000) {
    const now = Date.now();
    for (const [k, v] of recentFingerprints) {
      if (v < now) recentFingerprints.delete(k);
    }
  }
  return false;
}

// ─── Core createIncident() ───────────────────────────────────────────────────

/**
 * Create an incident through the full ISO 27035 workflow.
 * Identical to a human report — only `source` and `actorRole` differ.
 *
 * @param {{
 *   source: IncidentSource,
 *   category: string,
 *   title: string,
 *   description?: string|null,
 *   severity?: string|null,
 *   machine_id?: string|null,
 *   ip?: string|null,
 *   metadata?: object,
 *   io?: import('socket.io').Server,
 * }} payload
 * @returns {Promise<{ incidentId: string, severity: string, evidenceHash: string, workflow_phase: string, sla_due_at: Date|null }>}
 */
async function createIncident({ source, category, title, description, severity: forcedSeverity, machine_id, ip, metadata = {}, io }) {
  if (!VALID_SOURCES.includes(source)) {
    throw new Error(`Invalid source: ${source}`);
  }

  const effectiveCategory = VALID_CATEGORIES.includes(category) ? category : 'other';
  const { severity: triageSeverity, checklist } = triage(effectiveCategory);
  const severity = (forcedSeverity && ['critical', 'high', 'medium', 'low'].includes(forcedSeverity))
    ? forcedSeverity
    : triageSeverity;

  const incidentId = uuidv4();
  const now = new Date();
  const workflowState = buildInitialIncidentState({ severity, referenceAt: now });

  const evidenceHash = hashIncident({
    id: incidentId,
    timestamp: now.toISOString(),
    category: effectiveCategory,
    description: description || '',
  });

  // Detect-phase note reflects the actual origin
  const detectNotes = {
    SYSTEM_SCANNER: 'Appareil inconnu détecté automatiquement par le scanner réseau.',
    LOG_WATCHER: 'Activité suspecte détectée automatiquement par le lecteur de journaux système.',
    SIEM: 'Alerte reçue depuis un SIEM externe via webhook authentifié.',
    USER: 'Incident détecté et saisi depuis l\'application de bureau.',
    SYSTEM: 'Incident généré automatiquement par le module de détection Guardian (sans intervention humaine).',
  };

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    await conn.query(
      `INSERT INTO incidents
         (id, user_id, anonymous, machine_id, ip_address, category, severity, title, description,
          status, source, workflow_phase, workflow_state, sla_due_at, sla_warning_at, sla_breached_at,
          escalation_level, last_transition_at, evidence_hash, metadata)
       VALUES (?, NULL, 0, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        incidentId,
        machine_id || null,
        ip || null,
        effectiveCategory,
        severity,
        title,
        description || null,
        source,
        workflowState.workflowPhase,
        workflowState.workflowState,
        workflowState.slaDueAt,
        workflowState.slaWarningAt,
        workflowState.slaBreachedAt,
        workflowState.escalationLevel,
        workflowState.lastTransitionAt,
        evidenceHash,
        JSON.stringify({ ...metadata, auto_detect_source: source }),
      ]
    );

    await appendAuditLog(conn, {
      incidentId,
      actorId: null,
      actorRole: source === 'USER' ? 'employee' : 'system',
      action: 'created',
      newValue: { category: effectiveCategory, severity, source, workflow_phase: workflowState.workflowPhase },
      ipAddress: ip || null,
      createdAt: now,
    });

    const workflowEvents = buildInitialWorkflowEvents({ incidentId, createdAt: now, severity });
    // Override the detect-phase note to reflect the automated source
    if (workflowEvents[0]) {
      workflowEvents[0].note = detectNotes[source] || workflowEvents[0].note;
    }

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

    if (io) {
      io.to('admins').emit('incident:new', {
        id: incidentId,
        title,
        category: effectiveCategory,
        severity,
        source,
        ip_address: ip || null,
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
        title,
        category: effectiveCategory,
        severity,
        source,
        status: 'open',
        workflow_phase: workflowState.workflowPhase,
        workflow_state: workflowState.workflowState,
        escalation_level: workflowState.escalationLevel,
        machine_id: machine_id || null,
        ip_address: ip || null,
        description: description || null,
        assigned_to: null,
        assigned_user_name: null,
        assigned_team: null,
      },
    }).catch((err) => console.error('[auto-detect] Notification error:', err));

    console.log(`[auto-detect] Incident created — id=${incidentId} source=${source} category=${effectiveCategory} severity=${severity}`);
    return {
      incidentId,
      severity,
      evidenceHash,
      workflow_phase: workflowState.workflowPhase,
      sla_due_at: workflowState.slaDueAt,
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

// ─── 1. Network Scanner (nmap-like TCP probe) ─────────────────────────────────

/**
 * Probe a single TCP port to determine if a host is alive.
 * ECONNREFUSED counts as alive (host up, port closed).
 *
 * @param {string} host
 * @param {number} port
 * @param {number} timeoutMs
 * @returns {Promise<boolean>}
 */
function probeHost(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let alive = false;

    // Disable Nagle's algorithm so TCP SYN/RST packets are sent immediately.
    socket.setNoDelay(true);
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => { alive = true; socket.destroy(); });
    socket.on('timeout', () => socket.destroy());
    socket.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') alive = true; // Host up, port closed
      socket.destroy();
    });
    socket.on('close', () => resolve(alive));
    socket.connect(port, host);
  });
}

/**
 * Probe multiple TCP ports on a host concurrently.
 * Returns which port responded first (or null if none).
 * A host is considered alive if at least one port responds.
 *
 * @param {string} host
 * @param {number[]} ports
 * @param {number} timeoutMs
 * @returns {Promise<{ alive: boolean, openPort: number|null }>}
 */
async function probeAnyPort(host, ports, timeoutMs) {
  if (ports.length === 1) {
    const alive = await probeHost(host, ports[0], timeoutMs);
    return { alive, openPort: alive ? ports[0] : null };
  }
  // Short-circuit: resolve immediately when the first port responds alive.
  // All port probes start in parallel; dead hosts wait for all to time out together.
  return new Promise((resolve) => {
    let settled = 0;
    let resolved = false;
    const total = ports.length;
    for (const port of ports) {
      probeHost(host, port, timeoutMs).then((alive) => {
        settled++;
        if (alive && !resolved) {
          resolved = true;
          resolve({ alive: true, openPort: port });
        } else if (settled === total && !resolved) {
          resolve({ alive: false, openPort: null });
        }
      });
    }
  });
}

/**
 * Guess the OS family from the first responding port.
 * @param {number|null} port
 * @returns {'windows'|'linux'|'server'|'unknown'}
 */
function guessOs(port) {
  if (!port) return 'unknown';
  if (port === 445 || port === 135) return 'windows';
  if (port === 22 || port === 631) return 'linux';
  if (port === 80 || port === 443) return 'server';
  return 'unknown';
}

/**
 * Expand a /24 CIDR block into 254 host addresses.
 * Only /24 subnets are supported to keep the scanner lightweight.
 *
 * @param {string} cidr  e.g. "192.168.1.0/24"
 * @returns {string[]}
 */
function expandSubnet(cidr) {
  const [base] = cidr.split('/');
  const parts = base.split('.').map(Number);
  if (parts.length !== 4) return [];
  const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
  return Array.from({ length: 254 }, (_, i) => `${prefix}.${i + 1}`);
}

/**
 * Rich host registry: ip → { ip, status, trusted, firstSeen, lastSeen, openPort, osHint, scanCount }
 * Persists across scans for the lifetime of the process.
 * @type {Map<string, { ip: string, status: string, trusted: boolean, firstSeen: string, lastSeen: string, openPort: number|null, osHint: string, scanCount: number }>}
 */
const hostRegistry = new Map();
let scannerInitialized = false;
let _scannerTask = null;
// Config snapshot for the REST endpoint
let _scannerConfig = { subnets: [], probePorts: [], cronExpr: '' };

/** Return current registry as a sorted array for API consumers */
function getHostRegistrySnapshot() {
  return [...hostRegistry.values()].sort((a, b) => {
    const order = { new_external: 0, external_seen_before: 1, new: 0, known: 2, local_trusted: 3, trusted: 3 };
    return (order[a.status] ?? 9) - (order[b.status] ?? 9) || a.ip.localeCompare(b.ip);
  });
}

/**
 * Classify a host status based on trust list, history, and whether baseline is done.
 *
 * Statuses:
 *   'local_trusted'        — in SCANNER_TRUSTED_IPS (approved, safe)
 *   'known'                — present during the initial baseline (was already on network)
 *   'new_external'         — appeared AFTER baseline, NOT trusted → FIRST detection
 *   'external_seen_before' — appeared AFTER baseline, NOT trusted → RECURRING (still suspicious)
 *
 * Rule: once a device is flagged as external/unknown it is NEVER silently promoted
 * to 'known'/'local_trusted'. Only adding its IP to SCANNER_TRUSTED_IPS can do that.
 *
 * @param {string}          ip
 * @param {object|undefined} existing   Previous registry entry (undefined if never seen)
 * @param {boolean}         isTrusted
 * @param {boolean}         initialized  true = baseline scan already completed
 * @returns {'local_trusted'|'known'|'new_external'|'external_seen_before'}
 */
function classifyStatus(ip, existing, isTrusted, initialized) {
  if (isTrusted) return 'local_trusted';

  // Baseline scan — device was already on network before monitoring started
  if (!initialized) return 'known';

  // Post-baseline: device is new (never recorded before)
  if (!existing) return 'new_external';

  const prev = existing.status;

  // Once flagged external/unknown, KEEP it flagged — never silently promote
  if (prev === 'new_external' || prev === 'external_seen_before') return 'external_seen_before';

  // Backward compat: old 'new' status = external_seen_before
  if (prev === 'new') return 'external_seen_before';

  // Baseline device seen again, or already trusted → preserve
  return prev; // 'known' | 'local_trusted' | 'trusted'
}

/**
 * Start the network scanner.
 *
 * On its first run it builds a baseline of live hosts without raising incidents.
 * Every subsequent run compares live hosts against the baseline and raises a
 * 'suspicious_activity' incident (source=SYSTEM_SCANNER) for each new device.
 *
 * Socket.io events emitted:
 *   scanner:scan_start     — scan begins  { totalHosts, subnets, probePort, startedAt }
 *   scanner:host_found     — per live IP  { ip, status, trusted, firstSeen, lastSeen, probePort, isNew }
 *   scanner:baseline       — first scan   { hosts[], subnets, probePort, scannedAt, durationMs }
 *   scanner:scan_complete  — each scan    { hosts[], knownCount, newCount, subnets, probePort, scannedAt, durationMs }
 *   scanner:device_detected— alert only  { ip, probePort, detectedAt }
 *
 * @param {import('socket.io').Server} [io]
 */
function startNetworkScanner(io) {
  const scanIntervalMs = parseInt(process.env.SCANNER_INTERVAL_MS ?? '10000', 10);
  const cronExpr     = process.env.SCANNER_CRON            || '*/5 * * * *';
  const subnets      = (process.env.SCANNER_SUBNETS        || '192.168.1.0/24').split(',').map((s) => s.trim()).filter(Boolean);
  const trustedIps   = new Set((process.env.SCANNER_TRUSTED_IPS || '').split(',').map((s) => s.trim()).filter(Boolean));
  // Support SCANNER_PROBE_PORTS (multi) or legacy SCANNER_PROBE_PORT (single)
  const probePorts   = (process.env.SCANNER_PROBE_PORTS || process.env.SCANNER_PROBE_PORT || '22,445,80')
    .split(',').map((p) => parseInt(p.trim(), 10)).filter((p) => !isNaN(p) && p > 0);
  const probeTimeout = parseInt(process.env.SCANNER_PROBE_TIMEOUT_MS || '300', 10);

  _scannerConfig = { subnets, probePorts, cronExpr: scanIntervalMs > 0 ? null : cronExpr, intervalMs: scanIntervalMs > 0 ? scanIntervalMs : null };

  async function runScan() {
    const scanStart  = Date.now();
    const allHosts   = subnets.flatMap(expandSubnet);
    const now        = new Date().toISOString();

    if (io) {
      io.to('admins').emit('scanner:scan_start', {
        totalHosts: allHosts.length,
        subnets,
        probePorts,
        startedAt: now,
      });
    }

    const liveHosts = [];
    const newDevices = [];

    // Probe all hosts fully in parallel — no batching.
    // Each host result is processed immediately as its probe resolves,
    // so new-device events fire the moment a host is confirmed alive.
    await Promise.all(
      allHosts.map(async (h) => {
        const { alive, openPort } = await probeAnyPort(h, probePorts, probeTimeout);
        if (!alive) return;

        liveHosts.push(h);

        const existing  = hostRegistry.get(h);
        const isTrusted = trustedIps.has(h);
        const status    = classifyStatus(h, existing, isTrusted, scannerInitialized);
        const osHint    = guessOs(openPort);
        const entry     = {
          ip:        h,
          status,
          trusted:   isTrusted,
          firstSeen: existing?.firstSeen || now,
          lastSeen:  now,
          openPort,
          osHint,
          scanCount: (existing?.scanCount || 0) + 1,
        };
        hostRegistry.set(h, entry);

        // Emit per-host real-time event immediately
        if (io) {
          io.to('admins').emit('scanner:host_found', { ...entry, isNew: status === 'new_external' });
        }

        // Immediately detect & alert new device mid-scan (don't wait for full scan to finish)
        if (scannerInitialized && status === 'new_external') {
          const fingerprint = `scanner:${h}`;
          if (!isDuplicate(fingerprint)) {
            newDevices.push(h);
            console.warn(`[scanner] Unknown device detected: ${h}`);

            if (io) {
              io.to('admins').emit('scanner:device_detected', {
                ip: h,
                openPort: entry.openPort || null,
                osHint:   entry.osHint || 'unknown',
                detectedAt: now,
              });
            }

            createIncident({
              source: 'SYSTEM_SCANNER',
              category: 'suspicious_activity',
              title: `Appareil inconnu détecté sur le réseau — ${h}`,
              description:
                `Un appareil non répertorié (IP: ${h}) a répondu sur le port TCP ${entry.openPort || '?'} ` +
                `(OS probable: ${entry.osHint || 'inconnu'}). ` +
                `Vérification requise par l'équipe IT. Sous-réseau analysé: ${subnets.join(', ')}.`,
              machine_id: h,
              ip: h,
              metadata: { detected_ip: h, open_port: entry.openPort, os_hint: entry.osHint, subnets },
              io,
            }).catch((err) => console.error('[scanner] createIncident failed:', err));
          }
        }
      })
    );

    const scanDurationMs = Date.now() - scanStart;

    if (!scannerInitialized) {
      scannerInitialized = true;
      console.log(`[scanner] Baseline established: ${hostRegistry.size} known hosts on ${subnets.join(', ')}`);

      if (io) {
        io.to('admins').emit('scanner:baseline', {
          hosts: getHostRegistrySnapshot(),
          subnets,
          probePorts,
          scannedAt: now,
          durationMs: scanDurationMs,
        });
      }
      return;
    }

    if (io) {
      io.to('admins').emit('scanner:scan_complete', {
        hosts:      getHostRegistrySnapshot(),
        knownCount: [...hostRegistry.values()].filter((e) => e.status === 'known' || e.status === 'local_trusted' || e.status === 'trusted').length,
        newCount:   newDevices.length,
        subnets,
        probePorts,
        scannedAt:   now,
        durationMs:  scanDurationMs,
      });
    }
  }

  // Build baseline immediately, then schedule
  runScan().catch((err) => console.error('[scanner] Initial scan failed:', err));

  if (scanIntervalMs > 0) {
    // Fast sub-minute detection via setInterval
    _scannerTask = setInterval(() => {
      runScan().catch((err) => console.error('[scanner] Scan failed:', err));
    }, scanIntervalMs);
    console.log(`[scanner] Network scanner started — subnets: ${subnets.join(', ')} | ports: ${probePorts.join(',')} | interval: ${scanIntervalMs}ms`);
  } else {
    _scannerTask = cron.schedule(cronExpr, () => {
      runScan().catch((err) => console.error('[scanner] Scan failed:', err));
    }, { timezone: process.env.SCHEDULER_TIMEZONE || 'UTC' });
    console.log(`[scanner] Network scanner started — subnets: ${subnets.join(', ')} | ports: ${probePorts.join(',')} | cron: ${cronExpr}`);
  }
}

// ─── 2. Log Watcher ───────────────────────────────────────────────────────────

/**
 * Windows Security event IDs that indicate suspicious activity.
 * @type {Array<{ id: number, title: string, severity: string }>}
 */
const WINDOWS_EVENTS = [
  { id: 4625, title: 'Échec de connexion Windows (brute-force potentiel)',   severity: 'medium' },
  { id: 4648, title: 'Connexion avec identifiants explicites (RunAs / PTH)', severity: 'high'   },
  { id: 4720, title: 'Nouveau compte utilisateur créé',                       severity: 'high'   },
  { id: 4732, title: 'Utilisateur ajouté à un groupe privilégié',             severity: 'high'   },
  { id: 4776, title: "Échec d'authentification NTLM",                        severity: 'medium' },
  { id: 4778, title: 'Reconnexion de session à distance (mouvement latéral)', severity: 'medium' },
];

const WINDOWS_EVENT_MAP = Object.fromEntries(WINDOWS_EVENTS.map((e) => [e.id, e]));
const WINDOWS_EVENT_IDS = WINDOWS_EVENTS.map((e) => e.id);

/**
 * Linux auth.log regex patterns that indicate suspicious activity.
 * @type {Array<{ re: RegExp, category: string, severity: string, label: string }>}
 */
const LINUX_PATTERNS = [
  { re: /Failed password for(?: invalid user)? \S+ from ([\d.]+)/i, category: 'suspicious_activity', severity: 'medium', label: 'Brute-force SSH' },
  { re: /authentication failure.*user=(\S+)/i,                       category: 'suspicious_activity', severity: 'medium', label: 'Échec PAM' },
  { re: /sudo:\s+\S+\s+: command not allowed/i,                      category: 'suspicious_activity', severity: 'high',   label: 'Sudo non autorisé' },
  { re: /FAILED SU \(to root\)/i,                                    category: 'suspicious_activity', severity: 'high',   label: 'Tentative su root échouée' },
  { re: /useradd\[/i,                                                 category: 'suspicious_activity', severity: 'high',   label: 'Nouveau compte utilisateur créé' },
  { re: /groupadd\[/i,                                                category: 'suspicious_activity', severity: 'medium', label: 'Nouveau groupe créé' },
  { re: /POSSIBLE BREAK-IN ATTEMPT/i,                                 category: 'suspicious_activity', severity: 'high',   label: 'Tentative d\'intrusion (DNS inversé)' },
  { re: /Accepted publickey for root/i,                               category: 'suspicious_activity', severity: 'high',   label: 'Connexion root par clé publique SSH' },
];

/** @type {Date|null} */
let _lastWindowsCheckAt = null;
/** @type {number} Byte offset in Linux log file */
let _linuxLogPosition = 0;
let _logWatcherTask = null;

/**
 * Read Windows Security events since the last check and raise incidents
 * for every matching event ID.
 * @param {import('socket.io').Server} [io]
 */
async function checkWindowsLogs(io) {
  const since = _lastWindowsCheckAt
    ? _lastWindowsCheckAt.toISOString()
    : new Date(Date.now() - 60_000).toISOString();
  _lastWindowsCheckAt = new Date();

  const idList = WINDOWS_EVENT_IDS.join(',');
  // PowerShell: query Security log, emit CSV-like "id|truncatedMessage"
  const ps = [
    `Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime='${since}'; Id=${idList}}`,
    `-ErrorAction SilentlyContinue`,
    `| Select-Object -First 50`,
    `| ForEach-Object { $_.Id.ToString() + '|' + ($_.Message -replace '[\\r\\n]+',' ').Substring(0,[Math]::Min(300,$_.Message.Length)) }`,
    `| ConvertTo-Json -Compress`,
  ].join(' ');

  let stdout;
  try {
    ({ stdout } = await execAsync(`powershell -NonInteractive -Command "${ps.replace(/"/g, '\\"')}"`, { timeout: 12000 }));
  } catch (_err) {
    return; // No events or insufficient permissions — silent
  }

  const raw = (stdout || '').trim();
  if (!raw || raw === 'null') return;

  let entries;
  try {
    const parsed = JSON.parse(raw);
    entries = Array.isArray(parsed) ? parsed : [parsed];
  } catch (_err) {
    entries = raw.split('\n').filter(Boolean);
  }

  for (const entry of entries) {
    const line = typeof entry === 'string' ? entry : JSON.stringify(entry);
    const pipeIdx = line.indexOf('|');
    const eventId = parseInt(line.slice(0, pipeIdx), 10);
    const message = line.slice(pipeIdx + 1, pipeIdx + 301);
    const fingerprint = `winlog:${eventId}:${message.slice(0, 80)}`;

    if (isDuplicate(fingerprint)) continue;

    const meta = WINDOWS_EVENT_MAP[eventId];
    if (!meta) continue;

    createIncident({
      source: 'LOG_WATCHER',
      category: 'suspicious_activity',
      severity: meta.severity,
      title: meta.title,
      description: `Event ID ${eventId} détecté dans le journal Security Windows.\n${message}`,
      metadata: { event_id: eventId, platform: 'windows', raw: message },
      io,
    }).catch((err) => console.error('[log-watcher] createIncident failed:', err));
  }
}

/**
 * Read new lines appended to a Linux auth/syslog file and raise incidents
 * for lines matching suspicious patterns.
 * @param {import('socket.io').Server} [io]
 */
async function checkLinuxLogs(io) {
  const logFile = process.env.LOG_WATCHER_FILE || '/var/log/auth.log';

  let content;
  try {
    const stat = fs.statSync(logFile);
    if (stat.size < _linuxLogPosition) _linuxLogPosition = 0; // log rotation
    const length = stat.size - _linuxLogPosition;
    if (length <= 0) return;

    const buf = Buffer.allocUnsafe(length);
    const fd = fs.openSync(logFile, 'r');
    fs.readSync(fd, buf, 0, length, _linuxLogPosition);
    fs.closeSync(fd);
    _linuxLogPosition = stat.size;
    content = buf.toString('utf8');
  } catch (_err) {
    return; // File not accessible — silent
  }

  for (const line of content.split('\n').filter(Boolean)) {
    for (const { re, category, severity, label } of LINUX_PATTERNS) {
      if (!re.test(line)) continue;

      const fingerprint = `linuxlog:${label}:${line.slice(0, 100)}`;
      if (isDuplicate(fingerprint)) continue;

      createIncident({
        source: 'LOG_WATCHER',
        category,
        severity,
        title: `${label} détecté sur le système`,
        description: `Ligne suspecte détectée dans ${logFile}:\n${line.slice(0, 500)}`,
        metadata: { platform: 'linux', log_file: logFile, pattern: label, raw: line.slice(0, 500) },
        io,
      }).catch((err) => console.error('[log-watcher] createIncident failed:', err));

      break; // One incident per line — first matching pattern wins
    }
  }
}

/**
 * Start the log watcher.
 * Automatically picks the correct strategy based on os.platform().
 *
 * @param {import('socket.io').Server} [io]
 */
function startLogWatcher(io) {
  const cronExpr = process.env.LOG_WATCHER_CRON || '* * * * *';
  const platform = os.platform();

  async function runCheck() {
    if (platform === 'win32') {
      await checkWindowsLogs(io);
    } else {
      await checkLinuxLogs(io);
    }
  }

  _logWatcherTask = cron.schedule(cronExpr, () => {
    runCheck().catch((err) => console.error('[log-watcher] Check failed:', err));
  }, { timezone: process.env.SCHEDULER_TIMEZONE || 'UTC' });

  console.log(`[log-watcher] Log watcher started — platform: ${platform} | cron: ${cronExpr}`);
}

// ─── 3. SIEM Webhook — Express router ─────────────────────────────────────────

const siemRouter = express.Router();

const siemSchema = Joi.object({
  category:    Joi.string().valid(...VALID_CATEGORIES).default('suspicious_activity'),
  title:       Joi.string().min(3).max(200).required(),
  description: Joi.string().max(2000).allow('', null),
  severity:    Joi.string().valid('critical', 'high', 'medium', 'low').allow(null),
  machine_id:  Joi.string().max(200).allow('', null),
  metadata:    Joi.object().default({}),
});

/**
 * POST /api/auto-detect/siem
 *
 * Authenticated via the X-SIEM-Key request header.
 * Required env var: SIEM_WEBHOOK_SECRET
 *
 * Body:
 *   { category, title, description?, severity?, machine_id?, metadata? }
 *
 * Response 201:
 *   { success: true, incidentId, severity, evidenceHash, workflow_phase, sla_due_at }
 */
siemRouter.post('/siem', async (req, res) => {
  const expectedKey = process.env.SIEM_WEBHOOK_SECRET;
  if (!expectedKey) {
    return res.status(503).json({ error: 'SIEM webhook not configured (SIEM_WEBHOOK_SECRET missing)' });
  }

  const providedKey = req.headers['x-siem-key']
    || (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');

  // Constant-time comparison to prevent timing attacks
  let keyValid = false;
  try {
    const a = Buffer.from(providedKey || '');
    const b = Buffer.from(expectedKey);
    keyValid = a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (_err) {
    keyValid = false;
  }

  if (!keyValid) {
    return res.status(401).json({ error: 'Invalid or missing SIEM API key' });
  }

  const { error, value } = siemSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;

  try {
    const result = await createIncident({
      source: 'SIEM',
      category: value.category,
      title: value.title,
      description: value.description || null,
      severity: value.severity || undefined,
      machine_id: value.machine_id || null,
      ip,
      metadata: { ...value.metadata, siem_sender_ip: ip },
      io: req.app.get('io'),
    });

    return res.status(201).json({ success: true, ...result });
  } catch (err) {
    console.error('[siem] createIncident failed:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── REST: network host registry ─────────────────────────────────────────────

/**
 * GET /api/auto-detect/network/hosts
 * Returns the in-memory host registry built by the scanner.
 * Response: { initialized, hosts[], config }
 */
siemRouter.get('/network/hosts', (req, res) => {
  return res.json({
    initialized: scannerInitialized,
    hosts: getHostRegistrySnapshot(),
    config: _scannerConfig,
  });
});

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  /** Shared ISO 27035 incident factory — callable directly by any internal service */
  createIncident,
  /** Start the TCP network scanner (set AUTO_DETECT_SCANNER_ENABLED=true) */
  startNetworkScanner,
  /** Start the system log watcher (set AUTO_DETECT_LOG_WATCHER_ENABLED=true) */
  startLogWatcher,
  /** Express router — mount at /api/auto-detect */
  siemRouter,
};
