'use strict';

/**
 * routes/macIntel.js
 * ──────────────────
 * GET /api/mac-intel/:mac?ip=<ipv4>
 *   Returns full MAC intelligence: vendor, device type, trust status,
 *   spoofing detection, IP history, behavior analysis and risk score.
 *
 * The optional `ip` query param is used to cross-reference the live
 * host registry and record the MAC→IP sighting in the registry.
 */

const express = require('express');
const { getMacIntel, updateMacRegistry, isValidMac, normalizeMac } = require('../services/macIntelService');

const router = express.Router();

// ─── Validation helpers ───────────────────────────────────────────────────────

function isValidIpv4(ip) {
  if (typeof ip !== 'string') return false;
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  return ip.split('.').every((o) => { const n = parseInt(o, 10); return !isNaN(n) && n >= 0 && n <= 255; });
}

// ─── GET /api/mac-intel/:mac ──────────────────────────────────────────────────

router.get('/:mac', async (req, res) => {
  const rawMac = req.params.mac;
  const ipHint = req.query.ip || null;

  if (!isValidMac(rawMac)) {
    return res.status(400).json({ error: 'Invalid MAC address format. Expected XX:XX:XX:XX:XX:XX.' });
  }

  if (ipHint && !isValidIpv4(ipHint)) {
    return res.status(400).json({ error: 'Invalid IP address in query parameter.' });
  }

  const mac = normalizeMac(rawMac);

  try {
    const intel = await getMacIntel(mac, ipHint || null);

    // Record this sighting in the registry (non-fatal if it fails)
    if (ipHint) {
      try {
        updateMacRegistry(mac, ipHint, {
          osHints: intel.osHints,
        });
      } catch (_) { /* non-fatal */ }
    }

    return res.json(intel);
  } catch (err) {
    console.error('[mac-intel] Error for', mac, ':', err.message);
    return res.status(500).json({ error: 'MAC intelligence lookup failed', details: err.message });
  }
});

module.exports = router;
