'use strict';

/**
 * routes/deviceDetails.js
 * ─────────────────────────
 * GET  /api/device-details/:ip   — ARP + MAC vendor + nmap scan for an IP
 * POST /api/device-details/trust — Persist a MAC address as trusted
 *
 * Trust is stored by MAC address (not IP) in trusted-macs.json so it
 * survives address changes across DHCP renewals.
 */

const express  = require('express');
const { exec } = require('child_process');
const { promisify } = require('util');
const fs   = require('fs');
const path = require('path');

const router    = express.Router();
const execAsync = promisify(exec);

// ─── Paths ────────────────────────────────────────────────────────────────────

const REPORTS_DIR       = path.join(__dirname, '../../generated-reports');
const TRUSTED_MACS_FILE = path.join(REPORTS_DIR, 'trusted-macs.json');
const HOST_REGISTRY_FILE = path.join(REPORTS_DIR, 'host-registry.json');

// ─── Trusted MAC persistence ──────────────────────────────────────────────────

/** @returns {string[]} Normalized uppercase MAC addresses */
function loadTrustedMacs() {
  try {
    if (fs.existsSync(TRUSTED_MACS_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(TRUSTED_MACS_FILE, 'utf8'));
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (_) { /* first run or corrupt file */ }
  return [];
}

/** @param {string[]} macs */
function saveTrustedMacs(macs) {
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
  fs.writeFileSync(TRUSTED_MACS_FILE, JSON.stringify(macs, null, 2), 'utf8');
}

// ─── Validation helpers ───────────────────────────────────────────────────────

/**
 * Validate IPv4 to prevent command injection.
 * Only digits and dots in the strict a.b.c.d pattern are accepted.
 * @param {string} ip
 * @returns {boolean}
 */
function isValidIpv4(ip) {
  if (typeof ip !== 'string') return false;
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  return ip.split('.').every((o) => {
    const n = parseInt(o, 10);
    return !isNaN(n) && n >= 0 && n <= 255;
  });
}

/**
 * Validate MAC address format (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX).
 * @param {string} mac
 * @returns {boolean}
 */
function isValidMac(mac) {
  return typeof mac === 'string' &&
    /^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$/.test(mac);
}

/**
 * Normalize MAC to uppercase colon-separated (AA:BB:CC:DD:EE:FF).
 * @param {string} mac
 * @returns {string}
 */
function normalizeMac(mac) {
  return mac.toUpperCase().replace(/-/g, ':');
}

// ─── ARP lookup ───────────────────────────────────────────────────────────────

/**
 * Run a platform ARP lookup for `ip` and return the MAC address.
 * Validated IP is passed as a literal argument — no shell interpolation.
 * @param {string} ip Pre-validated IPv4 string
 * @returns {Promise<string|null>}
 */
async function arpLookup(ip) {
  try {
    const isWindows = process.platform === 'win32';
    // Pass IP as a separate argument to execAsync via array form when possible.
    // On Windows `arp -a <IP>` works; on Linux `arp -n <IP>`.
    const cmd = isWindows ? `arp -a ${ip}` : `arp -n ${ip}`;
    const { stdout } = await execAsync(cmd, { timeout: 5000 });

    // Match XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    const match = stdout.match(/([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}/);
    if (match) return normalizeMac(match[0]);
  } catch (_) { /* ARP not available or no entry */ }
  return null;
}

// ─── MAC vendor lookup ────────────────────────────────────────────────────────

/**
 * Offline OUI → vendor table for common prefixes.
 * Avoids external network calls for well-known manufacturers.
 */
const OUI_TABLE = {
  '00:50:56': 'VMware',
  '00:0C:29': 'VMware',
  '00:1C:14': 'VMware',
  '00:05:69': 'VMware',
  '08:00:27': 'Oracle VirtualBox',
  'B8:27:EB': 'Raspberry Pi Foundation',
  'DC:A6:32': 'Raspberry Pi Foundation',
  'E4:5F:01': 'Raspberry Pi Foundation',
  '00:23:AB': 'Cisco Systems',
  'D4:BE:D9': 'Cisco Systems',
  '00:1A:2B': 'Cisco Systems',
  'FC:FB:FB': 'Cisco Systems',
  '9C:20:7B': 'Netgear',
  'C4:04:15': 'Netgear',
  '74:D0:2B': 'Netgear',
  'AC:BC:32': 'Apple',
  '00:1C:B3': 'Apple',
  'F0:18:98': 'Apple',
  '3C:22:FB': 'Apple',
  '00:26:B9': 'Dell',
  '18:A9:9B': 'Dell',
  'BC:5F:F4': 'Dell',
  '40:16:7E': 'Intel',
  '00:1B:21': 'Intel',
  '7C:B0:C2': 'HP',
  'FC:15:B4': 'HP',
  '3C:D9:2B': 'HP',
  '00:17:88': 'Philips (Hue)',
  '00:03:7F': 'Atheros',
  '00:1D:0F': 'ASUS',
  '10:BF:48': 'TP-Link',
  '14:CF:92': 'TP-Link',
  '50:D4:F7': 'TP-Link',
  '00:22:3F': 'Samsung',
  '84:25:DB': 'Samsung',
  'A8:9F:BA': 'Huawei',
  '00:46:4B': 'Huawei',
};

/**
 * Return the vendor name for a MAC address.
 * Tries the offline OUI table first; falls back to the macvendors.com API.
 * @param {string|null} mac
 * @returns {Promise<string>}
 */
async function vendorLookup(mac) {
  if (!mac || mac === 'N/A') return 'Unknown';

  const oui = mac.substring(0, 8).toUpperCase();
  if (OUI_TABLE[oui]) return OUI_TABLE[oui];

  // Online fallback — best-effort, short timeout
  try {
    const axios = require('axios');
    const slug  = mac.replace(/:/g, '-');
    const { data } = await axios.get(`https://api.macvendors.com/${encodeURIComponent(slug)}`, {
      timeout: 2500,
    });
    if (typeof data === 'string' && data.length > 0) return data.trim();
  } catch (_) { /* API unavailable or rate-limited */ }

  return 'Unknown';
}

// ─── Nmap scan ────────────────────────────────────────────────────────────────

/**
 * Run an nmap scan against `ip` and extract open ports, OS, and hostname.
 * Degrades gracefully when nmap is not installed.
 * @param {string} ip Pre-validated IPv4 string
 * @returns {Promise<{ openPorts: number[], os: string, hostname: string }>}
 */
async function nmapScan(ip) {
  try {
    // -sV: service detection  -O: OS detection  -T4: aggressive timing
    // --host-timeout: cap the total scan time
    const { stdout } = await execAsync(
      `nmap -sV -O --host-timeout 12s -T4 ${ip}`,
      { timeout: 16000 }
    );

    // Open ports
    const portMatches = [...stdout.matchAll(/(\d+)\/tcp\s+open/g)];
    const openPorts   = portMatches.map((m) => parseInt(m[1], 10));

    // OS details
    let os = 'Unknown';
    const osDetail = stdout.match(/OS details:\s+(.+)/);
    if (osDetail) {
      os = osDetail[1].trim();
    } else {
      const aggGuess = stdout.match(/Aggressive OS guesses:\s+(.+)/);
      if (aggGuess) os = aggGuess[1].split(',')[0].trim();
    }

    // Hostname (e.g. "Nmap scan report for MYPC (192.168.1.10)")
    let hostname = ip;
    const hostnameMatch = stdout.match(/Nmap scan report for (.+?) \(/);
    if (hostnameMatch) hostname = hostnameMatch[1].trim();

    return { openPorts, os, hostname };
  } catch (_) {
    // nmap unavailable — return empty scan result
    return { openPorts: [], os: 'Unknown', hostname: ip };
  }
}

// ─── Device type inference ────────────────────────────────────────────────────

/**
 * Heuristically guess the device category.
 * @param {{ vendor: string, os: string, openPorts: number[] }} info
 * @returns {'PC / Server'|'Router'|'Mobile'|'IoT Device'|'Unknown'}
 */
function guessDeviceType({ vendor, os, openPorts }) {
  const v = (vendor || '').toLowerCase();
  const o = (os     || '').toLowerCase();

  if (v.includes('cisco') || v.includes('netgear') || v.includes('tp-link') ||
      v.includes('zyxel') || v.includes('ubiquiti') ||
      (openPorts.includes(53) && openPorts.length <= 6)) {
    return 'Router';
  }
  if (v.includes('raspberry') || v.includes('arduino') || v.includes('philips')) {
    return 'IoT Device';
  }
  if (o.includes('ios') || o.includes('android') ||
      (v.includes('apple') && openPorts.length <= 3)) {
    return 'Mobile';
  }
  if (o.includes('windows') || o.includes('linux') || o.includes('ubuntu') ||
      o.includes('debian')  || o.includes('centos') || o.includes('server')) {
    return 'PC / Server';
  }
  if (v.includes('vmware') || v.includes('virtualbox')) {
    return 'PC / Server';
  }
  return 'Unknown';
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * GET /api/device-details/:ip
 *
 * Runs ARP + vendor lookup + nmap for the given IP.
 * Returns rich device metadata including trust status (keyed on MAC).
 */
router.get('/:ip', async (req, res) => {
  const { ip } = req.params;

  if (!isValidIpv4(ip)) {
    return res.status(400).json({ error: 'Invalid IP address' });
  }

  try {
    // Load host registry for firstSeen / lastSeen
    let registryEntry = null;
    try {
      const raw = fs.readFileSync(HOST_REGISTRY_FILE, 'utf8');
      const registry = JSON.parse(raw);
      registryEntry = Array.isArray(registry)
        ? registry.find((h) => h.ip === ip) || null
        : null;
    } catch (_) { /* scanner may not be running */ }

    // Run ARP and nmap in parallel
    const [mac, nmapResult] = await Promise.all([
      arpLookup(ip),
      nmapScan(ip),
    ]);

    // Vendor lookup after ARP (depends on MAC result)
    const vendor = await vendorLookup(mac);

    // Trust status: MAC-based trusted list takes precedence
    const trustedMacs  = loadTrustedMacs();
    const normalizedMac = mac ? normalizeMac(mac) : null;

    let trusted = 'unknown';
    if (normalizedMac && trustedMacs.includes(normalizedMac)) {
      trusted = 'trusted';
    } else if (
      registryEntry?.status === 'local_trusted' ||
      registryEntry?.status === 'trusted'
    ) {
      trusted = 'trusted';
    } else if (
      registryEntry?.status === 'new_external' ||
      registryEntry?.status === 'external_seen_before' ||
      registryEntry?.status === 'new'
    ) {
      trusted = 'suspicious';
    }

    const deviceType = guessDeviceType({
      vendor,
      os: nmapResult.os,
      openPorts: nmapResult.openPorts,
    });

    return res.json({
      ip,
      mac:        mac || 'N/A',
      hostname:   nmapResult.hostname || ip,
      vendor,
      deviceType,
      os:         nmapResult.os,
      openPorts:  nmapResult.openPorts,
      firstSeen:  registryEntry?.firstSeen  || null,
      lastSeen:   registryEntry?.lastSeen   || null,
      trusted,
    });
  } catch (err) {
    console.error('[device-details] Scan error for', ip, ':', err.message);
    return res.status(500).json({ error: 'Scan failed', details: err.message });
  }
});

/**
 * POST /api/device-details/trust
 * Body: { mac: string }
 *
 * Persists a MAC address in the trusted-macs.json registry.
 * Uses MAC address as the stable unique identifier — never IP.
 */
router.post('/trust', (req, res) => {
  const { mac } = req.body || {};

  if (!mac) {
    return res.status(400).json({ error: 'mac is required' });
  }
  if (!isValidMac(mac)) {
    return res.status(400).json({ error: 'Invalid MAC address format' });
  }

  const normalized = normalizeMac(mac);
  const trustedMacs = loadTrustedMacs();

  if (!trustedMacs.includes(normalized)) {
    trustedMacs.push(normalized);
    saveTrustedMacs(trustedMacs);
  }

  return res.json({
    success: true,
    mac:     normalized,
    message: 'Device added to trusted list',
  });
});

module.exports = router;
