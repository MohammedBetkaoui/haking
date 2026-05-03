'use strict';

/**
 * siem-webhook.controller.js
 * ──────────────────────────
 * GUARDIAN — Récepteur d'alertes SIEM externes (Source 3)
 *
 * Normes appliquées :
 *   ISO 27001 A.16.1.2  — Signalement des événements de sécurité
 *   NIST CSF RS.CO-2    — Coordination de la réponse aux incidents
 *   NIST SP 800-61      — Guide de réponse — phase Containment/Eradication
 *   ISO 27035           — Workflow de traitement (detect → report → assess → respond → learn)
 *
 * Endpoints exposés (montés sur /api/siem) :
 *
 *   POST /api/siem/splunk    — Splunk HTTP Event Collector (HEC)
 *   POST /api/siem/elastic   — Elastic Security / Kibana SIEM webhook
 *   POST /api/siem/qradar    — IBM QRadar offense webhook (JSON)
 *   POST /api/siem/sentinel  — Microsoft Sentinel Logic App HTTP trigger
 *   POST /api/siem/generic   — Format Guardian natif (tout autre outil)
 *   GET  /api/siem/health    — Statut de l'intégration (healthcheck)
 *
 * Authentification par vendor :
 *   Splunk   → en-tête  Authorization: Splunk <token>   (SIEM_SPLUNK_TOKEN)
 *   Elastic  → HMAC-SHA256 sur le corps brut             (SIEM_ELASTIC_SECRET)
 *              en-tête  x-elastic-signature: sha256=<hex>
 *   QRadar   → en-tête  X-QRadar-Token: <token>          (SIEM_QRADAR_TOKEN)
 *   Sentinel → HMAC-SHA256 sur le corps brut             (SIEM_SENTINEL_SECRET)
 *              en-tête  x-sentinel-signature: sha256=<hex>
 *   Generic  → en-tête  X-SIEM-Key: <key>                (SIEM_WEBHOOK_SECRET)
 *              ou Authorization: Bearer <key>
 *
 * Tous les incidents sont injectés via createIncident() avec source='SIEM'
 * — même workflow ISO 27035 qu'un signalement humain.
 *
 * Variables d'environnement :
 *   SIEM_SPLUNK_TOKEN         Token Splunk HEC
 *   SIEM_ELASTIC_SECRET       Secret HMAC pour Elastic
 *   SIEM_QRADAR_TOKEN         Token QRadar
 *   SIEM_SENTINEL_SECRET      Secret HMAC pour Sentinel
 *   SIEM_WEBHOOK_SECRET       Clé générique (compatible avec l'ancienne route)
 *   SIEM_RATE_LIMIT_MAX       Requêtes max par fenêtre (défaut: 100)
 *   SIEM_RATE_LIMIT_WINDOW_MS Fenêtre rate limit en ms  (défaut: 60000)
 */

const crypto  = require('crypto');
const express = require('express');
const Joi     = require('joi');
const rateLimitModule = require('express-rate-limit');

const { createIncident } = require('../services/auto-detection.service');

/** @type {any} */
const rateLimit = rateLimitModule.rateLimit || rateLimitModule.default || rateLimitModule;

// ─── Configuration ────────────────────────────────────────────────────────────

const RATE_LIMIT_MAX       = parseInt(process.env.SIEM_RATE_LIMIT_MAX        || '100', 10);
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.SIEM_RATE_LIMIT_WINDOW_MS  || '60000', 10);

/**
 * Catégories valides Guardian.
 * Tout libellé SIEM inconnu sera mappé vers 'suspicious_activity' (défaut sûr).
 */
const VALID_CATEGORIES = new Set([
  'ransomware', 'phishing', 'device_loss', 'data_breach', 'suspicious_activity', 'other',
]);

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

// ─── Sécurité — helpers d'authentification ───────────────────────────────────

/**
 * Comparaison en temps constant (protection contre timing attacks).
 * Retourne true si les deux chaînes sont identiques.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeCompare(a, b) {
  if (!a || !b) return false;
  try {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) {
      // Effectuer quand même la comparaison pour masquer la différence de timing
      crypto.timingSafeEqual(Buffer.alloc(bb.length), bb);
      return false;
    }
    return crypto.timingSafeEqual(ba, bb);
  } catch (_) {
    return false;
  }
}

/**
 * Vérifie une signature HMAC-SHA256 sur le corps brut de la requête.
 * Format attendu de l'en-tête : "sha256=<hexdigest>"
 *
 * @param {Buffer}  rawBody   Corps brut (Buffer)
 * @param {string}  secret    Secret partagé
 * @param {string}  header    Valeur de l'en-tête de signature
 * @returns {boolean}
 */
function verifyHmac(rawBody, secret, header) {
  if (!secret || !header || !rawBody) return false;
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');
  return safeCompare(header, expected);
}

// ─── Middleware — capture du corps brut pour HMAC ────────────────────────────

/**
 * Middleware express qui parse le JSON tout en conservant le corps brut (Buffer)
 * dans req.rawBody pour la vérification HMAC.
 * Utilisé sur les routes Elastic et Sentinel.
 */
function rawBodyParser(req, res, next) {
  let data = [];
  req.on('data', (chunk) => data.push(chunk));
  req.on('end', () => {
    const raw = Buffer.concat(data);
    req.rawBody = raw;
    try {
      req.body = JSON.parse(raw.toString('utf8'));
    } catch (_) {
      req.body = {};
    }
    next();
  });
  req.on('error', next);
}

// ─── Rate limiter partagé ─────────────────────────────────────────────────────

const siemRateLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max:      RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Trop de requêtes SIEM — réessayer plus tard.' },
});

// ─── Normalisation des catégories SIEM → Guardian ────────────────────────────

/**
 * Table de correspondance des catégories SIEM externes vers les catégories Guardian.
 * Insensible à la casse.
 */
const CATEGORY_MAP = {
  // Ransomware
  ransomware: 'ransomware', 'crypto-locker': 'ransomware', 'file-encryption': 'ransomware',
  // Phishing
  phishing: 'phishing', 'spear-phishing': 'phishing', 'whaling': 'phishing',
  'business-email-compromise': 'phishing', bec: 'phishing',
  // Fuite de données
  'data-breach': 'data_breach', data_breach: 'data_breach', exfiltration: 'data_breach',
  'data-leak': 'data_breach', dlp: 'data_breach',
  // Perte de matériel
  'device-loss': 'device_loss', device_loss: 'device_loss',
  'hardware-loss': 'device_loss', 'stolen-device': 'device_loss',
  // Activité suspecte (catch-all SIEM)
  malware: 'suspicious_activity', 'command-and-control': 'suspicious_activity',
  c2: 'suspicious_activity', apt: 'suspicious_activity', intrusion: 'suspicious_activity',
  'lateral-movement': 'suspicious_activity', 'privilege-escalation': 'suspicious_activity',
  'brute-force': 'suspicious_activity', 'port-scan': 'suspicious_activity',
  reconnaissance: 'suspicious_activity', 'credential-theft': 'suspicious_activity',
  backdoor: 'suspicious_activity', rootkit: 'suspicious_activity',
  'insider-threat': 'suspicious_activity', dos: 'suspicious_activity',
  ddos: 'suspicious_activity',
};

/**
 * Mappe un libellé SIEM externe vers une catégorie Guardian valide.
 * @param {string|undefined} raw
 * @returns {string}
 */
function normalizeCategory(raw) {
  if (!raw) return 'suspicious_activity';
  const key = String(raw).toLowerCase().replace(/\s+/g, '-');
  return CATEGORY_MAP[key] || (VALID_CATEGORIES.has(key) ? key : 'suspicious_activity');
}

/**
 * Normalise une sévérité SIEM (texte libre ou numérique) vers une sévérité Guardian.
 *
 * @param {string|number|undefined} raw
 * @returns {string}
 */
function normalizeSeverity(raw) {
  if (!raw) return null;
  const s = String(raw).toLowerCase().trim();

  // Correspondance directe
  if (VALID_SEVERITIES.has(s)) return s;

  // Niveaux numériques courants
  const n = parseInt(s, 10);
  if (!isNaN(n)) {
    if (n >= 9)       return 'critical';
    if (n >= 7)       return 'high';
    if (n >= 4)       return 'medium';
    return 'low';
  }

  // Libellés Elastic / QRadar / Sentinel
  const map = {
    'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low',
    // Elastic
    '4': 'critical', '3': 'high', '2': 'medium', '1': 'low',
    // Splunk
    'severity_critical': 'critical', 'severity_high': 'high',
    'severity_medium': 'medium', 'severity_low': 'low',
    // Sentinel
    'informational': 'low', 'warning': 'medium',
    // QRadar
    'unknown': null,
  };
  return map[s] || null;
}

/**
 * Extrait l'IP source depuis un tableau d'entités Sentinel.
 * @param {Array<{Type?: string, Address?: string}>} [entities]
 * @returns {string|null}
 */
function extractSentinelIp(entities) {
  if (!Array.isArray(entities)) return null;
  const ipEntity = entities.find(
    (e) => e && (e.Type === 'ip' || e.Type === 'Ip' || e.Type === 'IP')
  );
  return ipEntity?.Address || null;
}

// ─── Router ───────────────────────────────────────────────────────────────────

const router = express.Router();
router.use(siemRateLimiter);

// ─── GET /api/siem/health ────────────────────────────────────────────────────

/**
 * Healthcheck : liste les intégrations actives (secret configuré).
 * N'expose pas les valeurs des secrets — seulement leur présence.
 */
router.get('/health', (req, res) => {
  return res.json({
    status: 'ok',
    integrations: {
      splunk:   !!process.env.SIEM_SPLUNK_TOKEN,
      elastic:  !!process.env.SIEM_ELASTIC_SECRET,
      qradar:   !!process.env.SIEM_QRADAR_TOKEN,
      sentinel: !!process.env.SIEM_SENTINEL_SECRET,
      generic:  !!process.env.SIEM_WEBHOOK_SECRET,
    },
    ts: new Date().toISOString(),
  });
});

// ─── POST /api/siem/splunk ────────────────────────────────────────────────────

/**
 * Récepteur Splunk HTTP Event Collector (HEC).
 *
 * Authentification : en-tête  Authorization: Splunk <token>
 *
 * Payload Splunk HEC attendu :
 * {
 *   event: {
 *     category?:    string,
 *     title?:       string,
 *     description?: string,
 *     severity?:    string | number,
 *     src_ip?:      string,
 *     dest_ip?:     string,
 *     machine_id?:  string,
 *     metadata?:    object
 *   },
 *   sourcetype?: string,   ← utilisé comme catégorie de repli
 *   host?:       string,   ← utilisé comme machine_id de repli
 *   index?:      string,
 *   time?:       number    ← epoch seconds (ignoré, Guardian utilise NOW())
 * }
 *
 * Réponse 201 : { success: true, incidentId, severity, workflow_phase, sla_due_at }
 */
router.post('/splunk', express.json({ limit: '512kb' }), async (req, res) => {
  const expectedToken = process.env.SIEM_SPLUNK_TOKEN;
  if (!expectedToken) {
    return res.status(503).json({ error: 'Intégration Splunk non configurée (SIEM_SPLUNK_TOKEN manquant).' });
  }

  // Authentification : "Authorization: Splunk <token>"
  const authHeader   = req.headers['authorization'] || '';
  const providedToken = authHeader.startsWith('Splunk ') ? authHeader.slice(7).trim() : '';

  if (!safeCompare(providedToken, expectedToken)) {
    return res.status(401).json({ error: 'Token Splunk invalide ou manquant.' });
  }

  const body = req.body || {};
  const evt  = (typeof body.event === 'object' && body.event !== null) ? body.event : body;

  const category   = normalizeCategory(evt.category || body.sourcetype);
  const severity   = normalizeSeverity(evt.severity);
  const title      = String(evt.title || evt.name || evt.rule_name || body.sourcetype || 'Alerte Splunk').slice(0, 200);
  const description = evt.description || evt.message || evt.desc || null;
  const ip         = evt.src_ip || evt.source_ip || evt.dest_ip || null;
  const machineId  = evt.machine_id || evt.host || body.host || null;
  const senderIp   = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;

  try {
    const result = await createIncident({
      source: 'SIEM',
      category,
      title,
      description: description ? String(description).slice(0, 2000) : null,
      severity,
      machine_id: machineId,
      ip,
      metadata: {
        siem_vendor: 'splunk',
        sourcetype: body.sourcetype || null,
        host: body.host || null,
        index: body.index || null,
        siem_sender_ip: senderIp,
        raw_event: evt,
      },
      io: req.app.get('io'),
    });

    console.log(`[siem/splunk] Incident créé — id=${result.incidentId}`);
    return res.status(201).json({ success: true, ...result });
  } catch (err) {
    console.error('[siem/splunk] createIncident échoué :', err);
    return res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// ─── POST /api/siem/elastic ───────────────────────────────────────────────────

/**
 * Récepteur Elastic Security / Kibana SIEM webhook.
 *
 * Authentification : HMAC-SHA256 sur le corps brut
 *   en-tête : x-elastic-signature: sha256=<hexdigest>
 *   secret  : SIEM_ELASTIC_SECRET
 *
 * Payload Elastic Security (Detection Engine) :
 * {
 *   rule: {
 *     name:        string,
 *     description: string,
 *     severity:    'low' | 'medium' | 'high' | 'critical',
 *     risk_score:  number (0-100),
 *     tags:        string[]
 *   },
 *   kibana.alert.rule.name?: string,
 *   signal?: {
 *     rule: { name, severity, description },
 *     original_event?: { category, action }
 *   },
 *   // Champs ECS standard
 *   source?: { ip: string },
 *   host?:   { name: string, ip: string[] },
 *   event?:  { category: string[], action: string }
 * }
 */
router.post('/elastic', rawBodyParser, async (req, res) => {
  const secret = process.env.SIEM_ELASTIC_SECRET;
  if (!secret) {
    return res.status(503).json({ error: 'Intégration Elastic non configurée (SIEM_ELASTIC_SECRET manquant).' });
  }

  const sigHeader = req.headers['x-elastic-signature'] || req.headers['x-elastic-app-webhook-signature'] || '';
  if (!verifyHmac(req.rawBody, secret, sigHeader)) {
    return res.status(401).json({ error: 'Signature Elastic invalide.' });
  }

  const body   = req.body || {};
  // Support des deux formats : alert API v8.x et signal API v7.x
  const rule   = body.rule || body['kibana.alert.rule'] || (body.signal && body.signal.rule) || {};
  const signal = body.signal || {};
  const ecs    = body;

  const rawSeverity = rule.severity || signal.rule?.severity || body['kibana.alert.severity'];
  const rawCategory = (Array.isArray(ecs.event?.category) ? ecs.event.category[0] : ecs.event?.category)
    || (Array.isArray(signal.original_event?.category) ? signal.original_event.category[0] : null)
    || rule.tags?.[0];

  const category   = normalizeCategory(rawCategory);
  const severity   = normalizeSeverity(rawSeverity);
  const title      = String(
    rule.name
    || body['kibana.alert.rule.name']
    || signal.rule?.name
    || 'Alerte Elastic Security'
  ).slice(0, 200);
  const description = (rule.description || signal.rule?.description || body['kibana.alert.reason'] || null);

  // Extraction IP depuis ECS : source.ip ou host.ip[0]
  const ip = ecs.source?.ip
    || (Array.isArray(ecs.host?.ip) ? ecs.host.ip[0] : ecs.host?.ip)
    || null;
  const machineId = ecs.host?.name || ecs.host?.hostname || null;
  const senderIp  = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;

  try {
    const result = await createIncident({
      source: 'SIEM',
      category,
      title,
      description: description ? String(description).slice(0, 2000) : null,
      severity,
      machine_id: machineId,
      ip,
      metadata: {
        siem_vendor: 'elastic',
        risk_score: rule.risk_score ?? body['kibana.alert.risk_score'] ?? null,
        rule_tags: rule.tags || [],
        host: ecs.host || null,
        siem_sender_ip: senderIp,
      },
      io: req.app.get('io'),
    });

    console.log(`[siem/elastic] Incident créé — id=${result.incidentId}`);
    return res.status(201).json({ success: true, ...result });
  } catch (err) {
    console.error('[siem/elastic] createIncident échoué :', err);
    return res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// ─── POST /api/siem/qradar ────────────────────────────────────────────────────

/**
 * Récepteur IBM QRadar offense webhook.
 *
 * Authentification : en-tête  X-QRadar-Token: <token>
 *
 * QRadar envoie ses offenses via un script personnalisé (Custom Action) ou
 * une règle de corrélation avec action HTTP POST.
 *
 * Payload QRadar (JSON) attendu :
 * {
 *   offense_id?:         number,
 *   description:         string,
 *   offense_type_str?:   string,   ← type d'offense (catégorie)
 *   magnitude?:          number,   ← 1-10 → sévérité
 *   severity?:           number | string,
 *   source_ip?:          string,
 *   destination_ip?:     string,
 *   device_name?:        string,
 *   start_time?:         number,   ← epoch ms
 *   category?:           string,
 *   event_count?:        number
 * }
 */
router.post('/qradar', express.json({ limit: '512kb' }), async (req, res) => {
  const expectedToken = process.env.SIEM_QRADAR_TOKEN;
  if (!expectedToken) {
    return res.status(503).json({ error: 'Intégration QRadar non configurée (SIEM_QRADAR_TOKEN manquant).' });
  }

  const provided = req.headers['x-qradar-token'] || '';
  if (!safeCompare(provided, expectedToken)) {
    return res.status(401).json({ error: 'Token QRadar invalide ou manquant.' });
  }

  const body = req.body || {};

  // QRadar "magnitude" est sur 1-10 — le mapper vers Guardian
  const rawSeverity = body.severity ?? body.magnitude;
  const category    = normalizeCategory(body.offense_type_str || body.category);
  const severity    = normalizeSeverity(rawSeverity);

  const offenseId   = body.offense_id ? `#${body.offense_id}` : '';
  const title       = String(
    body.description || body.name || `Offense QRadar${offenseId}`
  ).slice(0, 200);

  const ip         = body.source_ip || body.destination_ip || null;
  const machineId  = body.device_name || null;
  const senderIp   = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;

  const description = [
    body.description || '',
    body.offense_type_str ? `Type d'offense : ${body.offense_type_str}` : '',
    body.event_count      ? `Nombre d'événements : ${body.event_count}` : '',
    body.source_ip        ? `IP source : ${body.source_ip}`            : '',
    body.destination_ip   ? `IP destination : ${body.destination_ip}`  : '',
  ].filter(Boolean).join('\n');

  try {
    const result = await createIncident({
      source: 'SIEM',
      category,
      title,
      description: description.slice(0, 2000) || null,
      severity,
      machine_id: machineId,
      ip,
      metadata: {
        siem_vendor: 'qradar',
        offense_id: body.offense_id || null,
        offense_type: body.offense_type_str || null,
        magnitude: body.magnitude || null,
        event_count: body.event_count || null,
        source_ip: body.source_ip || null,
        destination_ip: body.destination_ip || null,
        siem_sender_ip: senderIp,
      },
      io: req.app.get('io'),
    });

    console.log(`[siem/qradar] Incident créé — id=${result.incidentId}`);
    return res.status(201).json({ success: true, ...result });
  } catch (err) {
    console.error('[siem/qradar] createIncident échoué :', err);
    return res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// ─── POST /api/siem/sentinel ──────────────────────────────────────────────────

/**
 * Récepteur Microsoft Sentinel — Logic App HTTP trigger.
 *
 * Authentification : HMAC-SHA256 sur le corps brut
 *   en-tête : x-sentinel-signature: sha256=<hexdigest>
 *   secret  : SIEM_SENTINEL_SECRET
 *
 * Configuration dans Sentinel :
 *   Playbook (Logic App) → Action "HTTP" → POST vers cette URL
 *   Header : x-sentinel-signature: sha256=HMAC(body, SIEM_SENTINEL_SECRET)
 *
 * Payload Microsoft Sentinel (Logic App schema) :
 * {
 *   alertDisplayName:    string,
 *   description?:        string,
 *   severity:            'Informational' | 'Low' | 'Medium' | 'High',
 *   status?:             string,
 *   alertType?:          string,       ← utilisé comme catégorie
 *   entities?: [
 *     { Type: 'ip', Address: string },
 *     { Type: 'host', HostName: string },
 *     { Type: 'account', Name: string }
 *   ],
 *   workspaceId?:        string,
 *   subscriptionId?:     string,
 *   resourceGroupName?:  string,
 *   alertUri?:           string
 * }
 */
router.post('/sentinel', rawBodyParser, async (req, res) => {
  const secret = process.env.SIEM_SENTINEL_SECRET;
  if (!secret) {
    return res.status(503).json({ error: 'Intégration Sentinel non configurée (SIEM_SENTINEL_SECRET manquant).' });
  }

  const sigHeader = req.headers['x-sentinel-signature'] || '';
  if (!verifyHmac(req.rawBody, secret, sigHeader)) {
    return res.status(401).json({ error: 'Signature Sentinel invalide.' });
  }

  const body = req.body || {};

  const category   = normalizeCategory(body.alertType || body.tactics?.[0]);
  const severity   = normalizeSeverity(body.severity);
  const title      = String(body.alertDisplayName || body.title || 'Alerte Microsoft Sentinel').slice(0, 200);

  // Extraction IP / hostname depuis le tableau entities
  const entities  = Array.isArray(body.entities) ? body.entities : [];
  const ip        = extractSentinelIp(entities);
  const hostEntity = entities.find((e) => e && (e.Type === 'host' || e.Type === 'Host'));
  const machineId = hostEntity?.HostName || hostEntity?.FQDN || null;
  const senderIp  = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;

  // Description enrichie avec le contexte Sentinel
  const descParts = [
    body.description || '',
    body.tactics?.length ? `Tactiques MITRE : ${body.tactics.join(', ')}` : '',
    body.alertUri        ? `Lien Sentinel : ${body.alertUri}`             : '',
    body.workspaceId     ? `Workspace ID : ${body.workspaceId}`           : '',
  ].filter(Boolean);

  try {
    const result = await createIncident({
      source: 'SIEM',
      category,
      title,
      description: descParts.join('\n').slice(0, 2000) || null,
      severity,
      machine_id: machineId,
      ip,
      metadata: {
        siem_vendor: 'sentinel',
        alert_type: body.alertType || null,
        tactics: body.tactics || [],
        entities: entities.map((e) => ({ type: e.Type, value: e.Address || e.HostName || e.Name || null })),
        workspace_id: body.workspaceId || null,
        alert_uri: body.alertUri || null,
        siem_sender_ip: senderIp,
      },
      io: req.app.get('io'),
    });

    console.log(`[siem/sentinel] Incident créé — id=${result.incidentId}`);
    return res.status(201).json({ success: true, ...result });
  } catch (err) {
    console.error('[siem/sentinel] createIncident échoué :', err);
    return res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// ─── POST /api/siem/generic ───────────────────────────────────────────────────

/**
 * Endpoint générique Guardian — compatible avec tout outil SIEM
 * (ou avec les scripts personnalisés).
 *
 * Authentification : en-tête X-SIEM-Key: <key>
 *                    ou       Authorization: Bearer <key>
 *   secret : SIEM_WEBHOOK_SECRET
 *
 * Schema Joi :
 * {
 *   category?:    string,
 *   title:        string (3–200 caractères, obligatoire),
 *   description?: string (max 2000 caractères),
 *   severity?:    'critical' | 'high' | 'medium' | 'low',
 *   machine_id?:  string,
 *   ip?:          string (IPv4/IPv6 valide),
 *   metadata?:    object
 * }
 *
 * Réponse 201 : { success: true, incidentId, severity, evidenceHash, workflow_phase, sla_due_at }
 */

const genericSchema = Joi.object({
  category:    Joi.string().max(64).default('suspicious_activity'),
  title:       Joi.string().min(3).max(200).required(),
  description: Joi.string().max(2000).allow('', null).default(null),
  severity:    Joi.string().valid('critical', 'high', 'medium', 'low').allow(null).default(null),
  machine_id:  Joi.string().max(200).allow('', null).default(null),
  ip:          Joi.string().ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' }).allow('', null).default(null),
  metadata:    Joi.object().default({}),
});

router.post('/generic', express.json({ limit: '512kb' }), async (req, res) => {
  const expectedKey = process.env.SIEM_WEBHOOK_SECRET;
  if (!expectedKey) {
    return res.status(503).json({ error: 'Webhook générique non configuré (SIEM_WEBHOOK_SECRET manquant).' });
  }

  const provided = req.headers['x-siem-key']
    || (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '').trim();

  if (!safeCompare(provided, expectedKey)) {
    return res.status(401).json({ error: 'Clé API invalide ou manquante.' });
  }

  const { error, value } = genericSchema.validate(req.body, { stripUnknown: true });
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const senderIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;

  try {
    const result = await createIncident({
      source: 'SIEM',
      category: normalizeCategory(value.category),
      title: value.title,
      description: value.description || null,
      severity: value.severity || null,
      machine_id: value.machine_id || null,
      ip: value.ip || null,
      metadata: { ...value.metadata, siem_vendor: 'generic', siem_sender_ip: senderIp },
      io: req.app.get('io'),
    });

    console.log(`[siem/generic] Incident créé — id=${result.incidentId}`);
    return res.status(201).json({ success: true, ...result });
  } catch (err) {
    console.error('[siem/generic] createIncident échoué :', err);
    return res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// ─── Export ───────────────────────────────────────────────────────────────────

module.exports = router;
