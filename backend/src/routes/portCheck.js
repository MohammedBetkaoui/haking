'use strict';

/**
 * portCheck.js
 * ────────────
 * Routes :
 *
 *   POST /api/auto-detect/port-check
 *     → Lance un scan manuel des ports sur le serveur (ou IP fournie).
 *     → Crée des incidents ISO 27035 pour chaque port anormal.
 *     → Émet `scan:port-check:done` via Socket.IO.
 *
 *   GET  /api/auto-detect/port-check/report
 *     → Retourne la liste des incidents "port anormal" (Règle 2)
 *       sous forme JSON prêt à télécharger (rapport CSV/JSON).
 *
 * Authentification : aucune (accès interne Dashboard)
 * Rate limit       : 6 req / minute (scan coûteux en réseau)
 */

const express    = require('express');
const Joi        = require('joi');
const rateLimitModule = require('express-rate-limit');

const pool                          = require('../db/pool');
const { runLocalPortCheck }         = require('../auto-detection/network-scanner.service');

/** @type {any} */
const rateLimit = rateLimitModule.rateLimit || rateLimitModule.default || rateLimitModule;

const router = express.Router();

// Limite de débit — les scans sont coûteux
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      6,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Trop de vérifications — maximum 6 scans par minute.' },
});

// ─── POST /api/auto-detect/port-check ─────────────────────────────────────────

const checkSchema = Joi.object({
  ip: Joi.string()
    .ip({ version: ['ipv4'], cidr: 'forbidden' })
    .allow('', null)
    .default(null),
});

/**
 * Déclenche un scan de ports manuel.
 *
 * Body (optionnel) : { ip?: string }   IP cible (défaut : IP du serveur)
 *
 * Réponse 200 :
 * {
 *   target_ip:         string,
 *   scanned:           number,   // nombre total de ports testés
 *   open:              number[], // tous les ports ouverts
 *   abnormal:          number[], // ports hors liste blanche
 *   incidents_created: number,   // incidents levés
 *   ts:                string    // ISO timestamp
 * }
 */
router.post('/', scanLimiter, async (req, res) => {
  const { error, value } = checkSchema.validate(req.body || {}, { stripUnknown: true });
  if (error) return res.status(400).json({ error: error.details[0].message });

  const io = req.app.get('io');

  try {
    const result = await runLocalPortCheck(value.ip || undefined, io);
    return res.json({ ...result, ts: new Date().toISOString() });
  } catch (err) {
    console.error('[portCheck] runLocalPortCheck échoué :', err);
    return res.status(500).json({ error: 'Erreur lors du scan de ports.' });
  }
});

// ─── GET /api/auto-detect/port-check/report ───────────────────────────────────

/**
 * Retourne tous les incidents liés aux ports ouverts (Règle 2 du scanner réseau).
 *
 * Query params (tous optionnels) :
 *   limit  {number}   Max incidents retournés (défaut: 100, max: 500)
 *   format {string}   'json' (défaut) ou 'csv'
 *
 * Réponse JSON :
 * {
 *   report_type: 'open-port-incidents',
 *   generated_at: string,
 *   total: number,
 *   incidents: [ { id, title, ip_address, severity, status, created_at, metadata } ]
 * }
 *
 * Réponse CSV (format=csv) :
 *   Fichier attaché : open-port-report-<date>.csv
 */
router.get('/report', async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit || '100', 10), 500);
  const format = req.query.format === 'csv' ? 'csv' : 'json';

  try {
    // Incidents créés par le scanner réseau (source SYSTEM) avec rule=2 dans metadata
    // On filtre par JSON_CONTAINS pour cibler uniquement la Règle 2
    const [rows] = await pool.query(
      `SELECT
         id,
         title,
         ip_address,
         severity,
         status,
         workflow_phase,
         workflow_state,
         created_at,
         metadata
       FROM incidents
       WHERE source IN ('SYSTEM', 'SYSTEM_SCANNER')
         AND (
           JSON_EXTRACT(metadata, '$.rule') = 2
           OR title LIKE '%Port inhabituel%'
           OR title LIKE '%port-check%'
           OR title LIKE '%Vérif. manuelle%'
         )
       ORDER BY created_at DESC
       LIMIT ?`,
      [limit]
    );

    // Désérialise metadata si elle est stockée comme chaîne
    const incidents = rows.map((row) => ({
      ...row,
      metadata: typeof row.metadata === 'string'
        ? (() => { try { return JSON.parse(row.metadata); } catch (_) { return {}; } })()
        : (row.metadata || {}),
    }));

    if (format === 'csv') {
      const date = new Date().toISOString().slice(0, 10);
      const filename = `open-port-report-${date}.csv`;

      const header = 'ID,Title,IP Address,Severity,Status,Workflow Phase,Open Port,Created At\n';
      const lines  = incidents.map((inc) => {
        const port = inc.metadata?.open_port ?? '';
        // Échappement CSV simple : guillemets autour des champs contenant virgule/guillemet
        const esc  = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
        return [
          esc(inc.id),
          esc(inc.title),
          esc(inc.ip_address ?? ''),
          esc(inc.severity),
          esc(inc.status),
          esc(inc.workflow_phase),
          esc(port),
          esc(inc.created_at),
        ].join(',');
      });

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      return res.send(header + lines.join('\n'));
    }

    return res.json({
      report_type:  'open-port-incidents',
      generated_at: new Date().toISOString(),
      total:        incidents.length,
      incidents,
    });
  } catch (err) {
    console.error('[portCheck] Rapport échoué :', err);
    return res.status(500).json({ error: 'Erreur lors de la génération du rapport.' });
  }
});

module.exports = router;
