'use strict';

/**
 * macIntelService.js
 * ──────────────────
 * MAC-address-based device intelligence engine.
 *
 * Functions exposed:
 *   lookupVendor(mac)           → { vendor, confidence, source }
 *   detectDeviceType(vendor)    → string  e.g. 'Desktop', 'Router'
 *   detectSpoofing(mac)         → { detected, reason }
 *   analyzeMacBehavior(mac)     → { label, description, score, hours, unusualActivity }
 *   getConnectionHistory(mac)   → stored registry entry | null
 *   getMacIntel(mac, ipHint)    → full intelligence object
 *   updateMacRegistry(mac, ip, opts) → persisted entry
 *   isValidMac(mac)             → boolean
 *   normalizeMac(mac)           → 'AA:BB:CC:DD:EE:FF'
 */

const fs   = require('fs');
const path = require('path');

// ─── File paths ───────────────────────────────────────────────────────────────

const REPORTS_DIR        = path.join(__dirname, '../../generated-reports');
const MAC_REGISTRY_FILE  = path.join(REPORTS_DIR, 'mac-registry.json');
const TRUSTED_MACS_FILE  = path.join(REPORTS_DIR, 'trusted-macs.json');
const HOST_REGISTRY_FILE = path.join(REPORTS_DIR, 'host-registry.json');

// ─── Expanded OUI → Vendor table ─────────────────────────────────────────────

const OUI_TABLE = {
  // VMware / VirtualBox
  '00:50:56': 'VMware',              '00:0C:29': 'VMware',
  '00:1C:14': 'VMware',              '00:05:69': 'VMware',
  '08:00:27': 'Oracle VirtualBox',
  // Raspberry Pi
  'B8:27:EB': 'Raspberry Pi Foundation',
  'DC:A6:32': 'Raspberry Pi Foundation',
  'E4:5F:01': 'Raspberry Pi Foundation',
  '28:CD:C1': 'Raspberry Pi Foundation',
  // Cisco
  '00:23:AB': 'Cisco Systems',       'D4:BE:D9': 'Cisco Systems',
  '00:1A:2B': 'Cisco Systems',       'FC:FB:FB': 'Cisco Systems',
  '58:97:1E': 'Cisco Systems',       'A4:56:30': 'Cisco Systems',
  '00:17:0F': 'Cisco Systems',       'B4:A4:E3': 'Cisco Systems',
  '68:BD:AB': 'Cisco Systems',
  // Netgear
  '9C:20:7B': 'Netgear',             'C4:04:15': 'Netgear',
  '74:D0:2B': 'Netgear',             '20:E5:2A': 'Netgear',
  'A0:21:B7': 'Netgear',
  // Apple
  'AC:BC:32': 'Apple',               '00:1C:B3': 'Apple',
  'F0:18:98': 'Apple',               '3C:22:FB': 'Apple',
  'A8:51:AB': 'Apple',               '68:5B:35': 'Apple',
  'F4:F1:5A': 'Apple',               '8C:85:90': 'Apple',
  '00:88:65': 'Apple',               'D8:BB:C1': 'Apple',
  '14:98:77': 'Apple',               'B8:78:2E': 'Apple',
  // Dell
  '00:26:B9': 'Dell',                '18:A9:9B': 'Dell',
  'BC:5F:F4': 'Dell',                'F8:B1:56': 'Dell',
  '00:14:22': 'Dell',                'E4:B9:7A': 'Dell',
  // Intel (NICs)
  '40:16:7E': 'Intel',               '00:1B:21': 'Intel',
  'A4:C3:F0': 'Intel',               '8C:8D:28': 'Intel',
  '10:02:B5': 'Intel',               '5C:51:4F': 'Intel',
  '98:4F:EE': 'Intel',
  // HP / Hewlett-Packard
  '7C:B0:C2': 'HP',                  'FC:15:B4': 'HP',
  '3C:D9:2B': 'HP',                  'B4:99:BA': 'HP',
  '70:10:6F': 'HP',                  '00:1B:78': 'HP',
  // TP-Link
  '10:BF:48': 'TP-Link',             '14:CF:92': 'TP-Link',
  '50:D4:F7': 'TP-Link',             'C8:3A:35': 'TP-Link',
  '54:A7:03': 'TP-Link',             'B0:4E:26': 'TP-Link',
  '98:DA:C4': 'TP-Link',
  // Samsung
  '00:22:3F': 'Samsung',             '84:25:DB': 'Samsung',
  'F4:09:D8': 'Samsung',             'CC:07:AB': 'Samsung',
  '8C:77:12': 'Samsung',             '50:85:69': 'Samsung',
  // Huawei
  'A8:9F:BA': 'Huawei',              '00:46:4B': 'Huawei',
  '48:FD:8E': 'Huawei',              '20:F3:A3': 'Huawei',
  // ASUS
  '00:1D:0F': 'ASUS',                '2C:56:DC': 'ASUS',
  '10:BF:48': 'ASUS',                '90:E6:BA': 'ASUS',
  // Lenovo
  '00:23:AE': 'Lenovo',              'E8:2A:44': 'Lenovo',
  '5C:F3:70': 'Lenovo',
  // D-Link
  '00:1B:11': 'D-Link',              '1C:7E:E5': 'D-Link',
  '14:D6:4D': 'D-Link',              '28:10:7B': 'D-Link',
  // Ubiquiti
  'DC:9F:DB': 'Ubiquiti',            '80:2A:A8': 'Ubiquiti',
  '68:72:51': 'Ubiquiti',            '44:D9:E7': 'Ubiquiti',
  'FC:EC:DA': 'Ubiquiti',
  // Xerox / Printers
  '00:00:AA': 'Xerox',               '00:00:2A': 'Xerox',
  // Canon
  '00:1E:8F': 'Canon',               '80:C1:6E': 'Canon',
  // Epson
  '00:26:AB': 'Epson',               '60:45:CB': 'Epson',
  // Brother
  '00:80:92': 'Brother',             '00:1B:A9': 'Brother',
  // Microsoft
  '00:1D:D8': 'Microsoft',           '28:18:78': 'Microsoft',
  '7C:1E:52': 'Microsoft',           '00:0D:3A': 'Microsoft',
  // Google
  '54:60:09': 'Google',              'A4:77:33': 'Google',
  '00:1A:11': 'Google',
  // Amazon
  '44:65:0D': 'Amazon',              '74:C2:46': 'Amazon',
  'F0:F0:A4': 'Amazon',              'AC:63:BE': 'Amazon',
  // Sonos
  '00:0E:58': 'Sonos',               '94:9F:3E': 'Sonos',
  '5C:AA:FD': 'Sonos',
  // Nintendo
  '00:1F:C5': 'Nintendo',            '00:22:D7': 'Nintendo',
  '98:B6:E9': 'Nintendo',
  // Philips Hue
  '00:17:88': 'Philips Hue',         'EC:B5:FA': 'Philips Hue',
  // MikroTik
  '2C:C8:1B': 'MikroTik',            '64:D1:54': 'MikroTik',
  'B8:69:F4': 'MikroTik',
  // Zyxel
  '00:A0:C5': 'Zyxel',               'B0:B2:DC': 'Zyxel',
  // Aruba / HP Networking
  '00:0B:86': 'Aruba Networks',      '94:B4:0F': 'Aruba Networks',
  // Synology
  '00:11:32': 'Synology',
  // QNAP
  '00:08:9B': 'QNAP Systems',
};

// ─── Vendor → Device Type classification rules ────────────────────────────────

const VENDOR_DEVICE_RULES = [
  { patterns: ['cisco', 'netgear', 'tp-link', 'zyxel', 'ubiquiti', 'd-link', 'linksys',
               'mikrotik', 'juniper', 'aruba', 'fortinet', 'palo alto', 'watchguard'],
    type: 'Router' },
  { patterns: ['xerox', 'canon', 'epson', 'brother', 'lexmark', 'ricoh', 'kyocera',
               'konica', 'minolta', 'sharp printer', 'fujixerox'],
    type: 'Printer' },
  { patterns: ['raspberry', 'arduino', 'esp', 'particle', 'sonos', 'philips hue',
               'amazon', 'google', 'nest', 'ring', 'wyze', 'belkin wemo', 'nintendo',
               'playstation', 'synology', 'qnap'],
    type: 'IoT Device' },
  { patterns: ['samsung', 'huawei', 'xiaomi', 'oppo', 'oneplus', 'vivo', 'realme',
               'motorola', 'nokia', 'zte', 'alcatel', 'blackberry'],
    type: 'Smartphone' },
  { patterns: ['vmware', 'oracle virtualbox', 'parallels', 'xen', 'hyper-v'],
    type: 'Desktop' },
  { patterns: ['intel', 'dell', 'lenovo', 'acer', 'asus', 'toshiba', 'msi', 'gigabyte',
               'hp', 'hewlett', 'fujitsu', 'panasonic', 'nec'],
    type: 'Desktop' },
  { patterns: ['apple'], type: 'Laptop' },
  { patterns: ['microsoft'], type: 'Desktop' },
];

// ─── File I/O ─────────────────────────────────────────────────────────────────

function ensureReportsDir() {
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

/** @returns {Record<string, object>} */
function loadMacRegistry() {
  try {
    if (fs.existsSync(MAC_REGISTRY_FILE)) {
      return JSON.parse(fs.readFileSync(MAC_REGISTRY_FILE, 'utf8'));
    }
  } catch (_) {}
  return {};
}

function saveMacRegistry(registry) {
  ensureReportsDir();
  fs.writeFileSync(MAC_REGISTRY_FILE, JSON.stringify(registry, null, 2), 'utf8');
}

/** @returns {Set<string>} */
function loadTrustedMacs() {
  try {
    if (fs.existsSync(TRUSTED_MACS_FILE)) {
      const arr = JSON.parse(fs.readFileSync(TRUSTED_MACS_FILE, 'utf8'));
      if (Array.isArray(arr)) return new Set(arr);
    }
  } catch (_) {}
  return new Set();
}

/** @returns {Array<object>} */
function loadHostRegistry() {
  try {
    if (fs.existsSync(HOST_REGISTRY_FILE)) {
      const data = JSON.parse(fs.readFileSync(HOST_REGISTRY_FILE, 'utf8'));
      if (Array.isArray(data)) return data;
    }
  } catch (_) {}
  return [];
}

// ─── MAC utilities ────────────────────────────────────────────────────────────

/**
 * Normalize MAC to uppercase colon-separated (AA:BB:CC:DD:EE:FF).
 * @param {string} mac
 * @returns {string}
 */
function normalizeMac(mac) {
  return mac.replace(/-/g, ':').toUpperCase();
}

/**
 * @param {string} mac
 * @returns {boolean}
 */
function isValidMac(mac) {
  return (
    typeof mac === 'string' &&
    /^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$/.test(mac)
  );
}

/**
 * Returns the OUI prefix (first 3 octets, uppercase, colon-separated).
 * @param {string} mac Already normalized MAC
 * @returns {string}
 */
function getOui(mac) {
  return mac.substring(0, 8).toUpperCase();
}

// ─── Vendor lookup ────────────────────────────────────────────────────────────

/**
 * Look up the vendor for a MAC address.
 * Tries offline OUI table first, falls back to macvendors.com API.
 *
 * @param {string} mac Normalized MAC (AA:BB:CC:DD:EE:FF)
 * @returns {Promise<{ vendor: string, confidence: 'high'|'medium'|'low'|'unknown', source: string }>}
 */
async function lookupVendor(mac) {
  const oui = getOui(mac);

  if (OUI_TABLE[oui]) {
    return { vendor: OUI_TABLE[oui], confidence: 'high', source: 'local-oui' };
  }

  // Online API fallback
  try {
    const axios = require('axios');
    const slug  = mac.substring(0, 8).replace(/:/g, '-');
    const { data } = await axios.get(
      `https://api.macvendors.com/${encodeURIComponent(slug)}`,
      { timeout: 2500 }
    );
    if (typeof data === 'string' && data.trim().length > 0) {
      return { vendor: data.trim(), confidence: 'medium', source: 'macvendors-api' };
    }
  } catch (_) { /* API unavailable or rate-limited */ }

  return { vendor: 'Unknown', confidence: 'unknown', source: 'none' };
}

// ─── Device type detection ────────────────────────────────────────────────────

/**
 * Estimate device category from vendor name.
 * @param {string} vendor
 * @returns {'Desktop'|'Laptop'|'Smartphone'|'Tablet'|'Router'|'Printer'|'IoT Device'|'Unknown'}
 */
function detectDeviceType(vendor) {
  const v = (vendor || '').toLowerCase();
  for (const rule of VENDOR_DEVICE_RULES) {
    if (rule.patterns.some((p) => v.includes(p))) return rule.type;
  }
  return 'Unknown';
}

// ─── MAC spoofing / randomization detection ───────────────────────────────────

/**
 * Analyze a MAC address for signs of spoofing or OS privacy randomization.
 *
 * The locally-administered bit (bit 1 of first octet) is set by iOS, Android,
 * and Windows 11 when using randomized MACs for network privacy.
 *
 * @param {string} mac Normalized MAC
 * @returns {{ detected: boolean, reason: string|null }}
 */
function detectSpoofing(mac) {
  const firstOctet = parseInt(mac.split(':')[0], 16);

  // Multicast bit (bit 0) — invalid for a unicast device
  if ((firstOctet & 0x01) !== 0) {
    return { detected: true, reason: 'Multicast MAC — invalid for a unicast host' };
  }

  // Locally administered bit (bit 1) — set when MAC is randomized by the OS
  if ((firstOctet & 0x02) !== 0) {
    return {
      detected: true,
      reason: 'Locally administered MAC — likely OS-generated (iOS/Android/Windows privacy randomization)',
    };
  }

  // All-zero OUI
  if (mac.startsWith('00:00:00')) {
    return { detected: true, reason: 'All-zero OUI — invalid manufacturer identifier' };
  }

  // Broadcast
  if (mac === 'FF:FF:FF:FF:FF:FF') {
    return { detected: true, reason: 'Broadcast MAC address' };
  }

  return { detected: false, reason: null };
}

// ─── Duplicate MAC detection ──────────────────────────────────────────────────

/**
 * Returns true if the MAC was recorded as active on more than one IP
 * within the last hour (possible ARP spoofing / MAC conflict).
 *
 * @param {string} mac
 * @param {string|null} currentIp
 * @param {Record<string, object>} registry
 * @returns {boolean}
 */
function detectDuplicate(mac, currentIp, registry) {
  const entry = registry[mac];
  if (!entry?.ipHistory || entry.ipHistory.length <= 1) return false;

  const oneHourAgo = Date.now() - 3_600_000;
  const recentOtherIps = entry.ipHistory.filter(
    (h) => h.ip !== currentIp && new Date(h.lastSeen).getTime() > oneHourAgo
  );
  return recentOtherIps.length > 0;
}

// ─── Vendor mismatch detection ────────────────────────────────────────────────

/**
 * Flag if the vendor profile contradicts the observed OS/port behavior.
 *
 * @param {string} vendor
 * @param {{ osHint?: string }} hostEntry
 * @returns {boolean}
 */
function detectVendorMismatch(vendor, hostEntry) {
  if (!hostEntry || !vendor || vendor === 'Unknown') return false;

  const v   = vendor.toLowerCase();
  const os  = (hostEntry.osHint || '').toLowerCase();
  const ep  = ['windows', 'linux', 'server'];

  const isNetVendor     = ['cisco', 'netgear', 'tp-link', 'ubiquiti', 'd-link', 'mikrotik', 'zyxel'].some((n) => v.includes(n));
  const isPrinterVendor = ['xerox', 'canon', 'epson', 'brother', 'lexmark'].some((n) => v.includes(n));

  if (isNetVendor && ep.includes(os))     return true;
  if (isPrinterVendor && ep.includes(os)) return true;

  return false;
}

// ─── Behavior / activity pattern analysis ────────────────────────────────────

/**
 * Analyze 24-hour connection histogram to identify behavioral patterns.
 *
 * @param {object|null} entry MAC registry entry
 * @returns {{ label: string, description: string, score: number, hours: number[], unusualActivity: boolean }}
 */
function analyzeMacBehavior(entry) {
  const empty = new Array(24).fill(0);

  if (!entry?.connectionHours) {
    return { label: 'Unknown', description: 'No connection history recorded', score: 0, hours: empty, unusualActivity: false };
  }

  const hours = entry.connectionHours;
  const total = hours.reduce((s, v) => s + v, 0);
  if (total === 0) {
    return { label: 'Unknown', description: 'No activity recorded yet', score: 0, hours, unusualActivity: false };
  }

  // Business hours 08:00–18:00
  const officeCount = hours.slice(8, 19).reduce((s, v) => s + v, 0);
  // Late night 22:00–06:00
  const nightCount  = [...hours.slice(22), ...hours.slice(0, 7)].reduce((s, v) => s + v, 0);
  const activeBuckets = hours.filter((v) => v > 0).length;

  const officePct = officeCount / total;
  const nightPct  = nightCount  / total;

  let label, description, score, unusualActivity = false;

  if (activeBuckets >= 20) {
    label = 'Always On';
    description = 'Active around the clock — typical of servers or network infrastructure';
    score = 55;
  } else if (officePct >= 0.65) {
    label = 'Office Hours';
    description = 'Predominantly active during business hours (08:00–18:00)';
    score = 90;
  } else if (nightPct >= 0.55) {
    label = 'Night Activity';
    description = 'Mostly active at night (22:00–06:00) — warrants investigation';
    score = 35;
    unusualActivity = true;
  } else if (activeBuckets <= 4) {
    label = 'Sporadic';
    description = 'Very infrequent, irregular connections';
    score = 45;
    unusualActivity = activeBuckets <= 2;
  } else {
    label = 'Mixed Pattern';
    description = 'Activity spread across varied hours — no clear pattern';
    score = 55;
  }

  return { label, description, score, hours, unusualActivity };
}

// ─── Risk score ───────────────────────────────────────────────────────────────

/**
 * Compute a 0–100 risk score for a device.
 *
 * @param {{ trustStatus: string, spoofingDetected: boolean, duplicateDetected: boolean,
 *           vendorMismatch: boolean, unusualActivity: boolean, connectionCount: number }} opts
 * @returns {number}
 */
function computeRiskScore({ trustStatus, spoofingDetected, duplicateDetected, vendorMismatch, unusualActivity, connectionCount }) {
  let score = 0;

  const baseMap = { trusted: 5, unknown: 30, suspicious: 62, blocked: 88 };
  score += baseMap[trustStatus] ?? 30;

  if (spoofingDetected)  score += 20;
  if (duplicateDetected) score += 18;
  if (vendorMismatch)    score += 12;
  if (unusualActivity)   score += 10;

  // Bonus for well-known long-standing device
  if (connectionCount > 50) score = Math.max(score - 10, 0);

  return Math.min(Math.max(Math.round(score), 0), 100);
}

/**
 * @param {number} score 0–100
 * @returns {'low'|'medium'|'high'|'critical'}
 */
function getAlertLevel(score) {
  if (score <= 25) return 'low';
  if (score <= 50) return 'medium';
  if (score <= 75) return 'high';
  return 'critical';
}

// ─── Connection history (public helper) ──────────────────────────────────────

/**
 * Returns the raw registry entry for a MAC, or null if unknown.
 * @param {string} mac Normalized MAC
 * @returns {object|null}
 */
function getConnectionHistory(mac) {
  const registry = loadMacRegistry();
  return registry[mac] || null;
}

// ─── Registry updater ─────────────────────────────────────────────────────────

/**
 * Record a MAC sighting (called whenever a device scan returns a MAC+IP pair).
 * Idempotent — safe to call on every scan.
 *
 * @param {string} mac   Normalized MAC address
 * @param {string} ip    Current IPv4 address
 * @param {{ hostname?: string|null, osHint?: string|null, openPorts?: number[] }} opts
 * @returns {object}     Updated registry entry
 */
function updateMacRegistry(mac, ip, { hostname = null, osHint = null, openPorts = [] } = {}) {
  const registry = loadMacRegistry();
  const now      = new Date().toISOString();
  const hour     = new Date().getHours();

  let entry = registry[mac];

  if (!entry) {
    entry = {
      mac,
      oui: getOui(mac),
      currentIp: ip,
      ipHistory: [],
      hostname:  null,
      firstSeen: now,
      lastSeen:  now,
      connectionCount: 0,
      connectionHours: new Array(24).fill(0),
      osHints: [],
    };
  }

  entry.lastSeen    = now;
  entry.currentIp   = ip;
  entry.connectionCount = (entry.connectionCount || 0) + 1;

  // Ensure arrays exist (guard for old registry entries)
  if (!Array.isArray(entry.connectionHours)) entry.connectionHours = new Array(24).fill(0);
  if (!Array.isArray(entry.osHints))         entry.osHints = [];
  if (!Array.isArray(entry.ipHistory))        entry.ipHistory = [];

  entry.connectionHours[hour] = (entry.connectionHours[hour] || 0) + 1;

  if (hostname) entry.hostname = hostname;

  if (osHint && !entry.osHints.includes(osHint)) {
    entry.osHints.push(osHint);
  }

  // Update IP history
  const ipEntry = entry.ipHistory.find((h) => h.ip === ip);
  if (ipEntry) {
    ipEntry.lastSeen = now;
    ipEntry.count    = (ipEntry.count || 0) + 1;
  } else {
    entry.ipHistory.push({ ip, firstSeen: now, lastSeen: now, count: 1 });
  }

  registry[mac] = entry;
  saveMacRegistry(registry);

  return entry;
}

// ─── Main intelligence function ───────────────────────────────────────────────

/**
 * Build the full MAC intelligence object for a given MAC address.
 *
 * @param {string} mac          Normalized MAC (AA:BB:CC:DD:EE:FF)
 * @param {string|null} ipHint  Current IP hint (from caller or ARP)
 * @returns {Promise<object>}   Full intel payload
 */
async function getMacIntel(mac, ipHint = null) {
  const registry    = loadMacRegistry();
  const trustedMacs = loadTrustedMacs();
  const hostReg     = loadHostRegistry();

  const stored = registry[mac] || {};

  // ── Vendor & device type ─────────────────────────────────────────────────
  const { vendor, confidence: vendorConfidence, source: vendorSource } = await lookupVendor(mac);
  const deviceType = detectDeviceType(vendor);

  // ── Current IP resolution ─────────────────────────────────────────────────
  const currentIp = ipHint || stored.currentIp || null;

  // ── Cross-reference with host registry ────────────────────────────────────
  const hostEntry = currentIp ? hostReg.find((h) => h.ip === currentIp) : null;

  // ── Trust status ──────────────────────────────────────────────────────────
  let trustStatus = 'unknown';
  if (trustedMacs.has(mac)) {
    trustStatus = 'trusted';
  } else if (hostEntry?.status === 'local_trusted' || hostEntry?.status === 'trusted') {
    trustStatus = 'trusted';
  } else if (
    hostEntry?.status === 'new_external' ||
    hostEntry?.status === 'external_seen_before' ||
    hostEntry?.status === 'new'
  ) {
    trustStatus = 'suspicious';
  } else if (hostEntry?.status === 'known') {
    trustStatus = 'unknown';
  }

  // ── Security analysis ─────────────────────────────────────────────────────
  const spoofing         = detectSpoofing(mac);
  const duplicateDetected = detectDuplicate(mac, currentIp, registry);
  const vendorMismatch   = detectVendorMismatch(vendor, hostEntry);

  // ── Behavior analysis ─────────────────────────────────────────────────────
  const activityPattern = analyzeMacBehavior(stored);

  // ── Risk score ────────────────────────────────────────────────────────────
  const riskScore = computeRiskScore({
    trustStatus,
    spoofingDetected:  spoofing.detected,
    duplicateDetected,
    vendorMismatch,
    unusualActivity:   activityPattern.unusualActivity,
    connectionCount:   stored.connectionCount || 0,
  });

  // ── Derived fields ────────────────────────────────────────────────────────
  const subnet = currentIp
    ? (() => { const p = currentIp.split('.'); return `${p[0]}.${p[1]}.${p[2]}.0/24`; })()
    : null;

  const connectionCount = stored.connectionCount || hostEntry?.scanCount || 0;

  let sessionDurationAvg = null;
  if (stored.firstSeen && stored.lastSeen && connectionCount > 1) {
    const totalMs = new Date(stored.lastSeen).getTime() - new Date(stored.firstSeen).getTime();
    sessionDurationAvg = Math.round(totalMs / connectionCount / 1000);
  }

  // IP history: fall back to constructing from hostEntry if nothing stored
  const ipHistory =
    stored.ipHistory?.length > 0
      ? stored.ipHistory
      : currentIp
        ? [{ ip: currentIp,
             firstSeen: stored.firstSeen || hostEntry?.firstSeen || new Date().toISOString(),
             lastSeen:  stored.lastSeen  || hostEntry?.lastSeen  || new Date().toISOString(),
             count: connectionCount || 1 }]
        : [];

  const osHints = stored.osHints?.length > 0
    ? stored.osHints
    : hostEntry?.osHint ? [hostEntry.osHint] : [];

  const openPorts = hostEntry?.openPort ? [hostEntry.openPort] : [];

  // Reconnect frequency label
  let reconnectFrequency = 'unknown';
  if (connectionCount >= 100) reconnectFrequency = 'very frequent';
  else if (connectionCount >= 30) reconnectFrequency = 'frequent';
  else if (connectionCount >= 10) reconnectFrequency = 'regular';
  else if (connectionCount >= 3)  reconnectFrequency = 'occasional';
  else if (connectionCount >= 1)  reconnectFrequency = 'rare';

  return {
    mac,
    oui:                getOui(mac),
    vendor,
    vendorConfidence,
    vendorSource,
    deviceType,
    currentIp,
    ipHistory,
    hostname:           stored.hostname || null,
    subnet,
    firstSeen:          stored.firstSeen  || hostEntry?.firstSeen  || null,
    lastSeen:           stored.lastSeen   || hostEntry?.lastSeen   || null,
    connectionCount,
    sessionDurationAvg,
    reconnectFrequency,
    trustStatus,
    spoofingDetected:   spoofing.detected,
    spoofingReason:     spoofing.reason,
    duplicateDetected,
    vendorMismatch,
    riskScore,
    alertLevel:         getAlertLevel(riskScore),
    activityPattern,
    openPorts,
    osHints,
  };
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  lookupVendor,
  detectDeviceType,
  analyzeMacBehavior,
  detectSpoofing,
  getConnectionHistory,
  getMacIntel,
  updateMacRegistry,
  normalizeMac,
  isValidMac,
};
