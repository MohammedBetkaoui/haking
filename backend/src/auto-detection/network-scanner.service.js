'use strict';

/**
 * network-scanner.service.js
 * ──────────────────────────
 * GUARDIAN — Module de Détection Réseau Automatique (sans intervention humaine)
 *
 * Chaîne des normes :
 *   NIST CSF (Identify + Detect)
 *     ↓ détecte et remonte les événements
 *   ISO 27001 (Surveillance — définit quoi monitorer)
 *     ↓ définit les règles
 *   IDS/IPS + SIEM + EDR (détection technique)
 *     ↓ génère des alertes
 *   ISO 27035 (Detect → Report → Assess → Respond → Learn)
 *     ↓ workflow de traitement de l'incident
 *   NIST SP 800-61 (containment, eradication, recovery)
 *     ↓ guide de réponse
 *   Loi 18-07 (notification ANPDP obligatoire sous 72h)
 *
 * Quatre règles de détection indépendantes — tous les incidents sont injectés
 * dans le workflow ISO 27035 avec source: 'SYSTEM' (aucun employé impliqué).
 *
 * ┌──────────┬──────────────────────────────────────────────────────────────┐
 * │ RÈGLE 1  │ Appareil inconnu — MAC absent de la table known_devices      │
 * │          │ Sévérité : CRITICAL | Catégorie : suspicious_activity        │
 * ├──────────┼──────────────────────────────────────────────────────────────┤
 * │ RÈGLE 2  │ Port anormal ouvert — hors [80, 443, 22, 3389, 8080]        │
 * │          │ Sévérité : HIGH     | Catégorie : suspicious_activity        │
 * ├──────────┼──────────────────────────────────────────────────────────────┤
 * │ RÈGLE 3  │ Volume trafic sortant anormal — > 1 GB en < 10 min          │
 * │          │ Sévérité : CRITICAL | Catégorie : data_leak                  │
 * ├──────────┼──────────────────────────────────────────────────────────────┤
 * │ RÈGLE 4  │ Scan de ports — > 20 ports depuis la même IP en < 30 s      │
 * │          │ Sévérité : CRITICAL | Catégorie : intrusion_attempt          │
 * └──────────┴──────────────────────────────────────────────────────────────┘
 *
 * Variables d'environnement (toutes optionnelles) :
 *   NET_SCAN_ENABLED              'true' pour démarrer ce scanner (défaut: false)
 *   NET_SCAN_INTERVAL_MS          Intervalle entre les cycles (défaut: 60000 = 60 s)
 *   NET_SCAN_SUBNETS              CIDRs /24 séparés par virgule (défaut: 192.168.1.0/24)
 *   NET_SCAN_PROBE_TIMEOUT_MS     Timeout TCP par port (défaut: 800)
 *   NET_SCAN_TRAFFIC_THRESHOLD_GB Seuil de trafic sortant en GB (défaut: 1)
 *   NET_SCAN_PORT_SCAN_THRESHOLD  Nbre de ports distincts pour déclencher alerte (défaut: 20)
 *   NET_SCAN_PORT_SCAN_WINDOW_MS  Fenêtre glissante de détection scan (défaut: 30000)
 *   NET_SCAN_DEDUP_WINDOW_MS      Fenêtre de déduplication (défaut: 600000 = 10 min)
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const net = require('net');
const os = require('os');

const { v4: uuidv4 } = require('uuid');

const pool = require('../db/pool');
const { createIncident } = require('../services/auto-detection.service');

const execAsync = promisify(exec);

// ─── Configuration ────────────────────────────────────────────────────────────

const SCAN_INTERVAL_MS      = parseInt(process.env.NET_SCAN_INTERVAL_MS           || '60000', 10);
const PROBE_TIMEOUT_MS      = parseInt(process.env.NET_SCAN_PROBE_TIMEOUT_MS       || '800',   10);
const TRAFFIC_THRESHOLD_GB  = parseFloat(process.env.NET_SCAN_TRAFFIC_THRESHOLD_GB || '1');
const PORT_SCAN_THRESHOLD   = parseInt(process.env.NET_SCAN_PORT_SCAN_THRESHOLD    || '20',   10);
const PORT_SCAN_WINDOW_MS   = parseInt(process.env.NET_SCAN_PORT_SCAN_WINDOW_MS    || '30000', 10);
const DEDUP_WINDOW_MS       = parseInt(process.env.NET_SCAN_DEDUP_WINDOW_MS        || '600000', 10);

/**
 * Ports autorisés (RÈGLE 2) — tout port ouvert hors de cette liste déclenche un incident.
 * Référence : politique de sécurité réseau interne (ISO 27001 Annexe A.13).
 */
const ALLOWED_PORTS = new Set([80, 443, 22, 3389, 8080]);

/**
 * Ports sondés lors du balayage de service (RÈGLE 2).
 * Couvre les protocoles dangereux les plus courants : Telnet, FTP, SMB,
 * bases de données non protégées, VNC, Redis, Elasticsearch, MongoDB.
 */
const PROBE_PORTS = [
  21,    // FTP
  22,    // SSH
  23,    // Telnet (non chiffré)
  25,    // SMTP
  53,    // DNS
  80,    // HTTP
  110,   // POP3
  135,   // RPC (Windows)
  139,   // NetBIOS
  143,   // IMAP
  443,   // HTTPS
  445,   // SMB (Windows File Sharing)
  1433,  // Microsoft SQL Server
  1521,  // Oracle DB
  3306,  // MySQL / MariaDB
  3389,  // RDP (Remote Desktop)
  5432,  // PostgreSQL
  5900,  // VNC
  6379,  // Redis (non authentifié par défaut)
  8080,  // HTTP alternatif
  8443,  // HTTPS alternatif
  9200,  // Elasticsearch
  27017, // MongoDB
];

// ─── Déduplication ────────────────────────────────────────────────────────────

/** @type {Map<string, number>} fingerprint → timestamp d'expiration */
const _dedupMap = new Map();

/**
 * Vérifie si un événement est un doublon (même fingerprint dans la fenêtre).
 * Thread-safe pour l'usage single-threaded de Node.js.
 * @param {string} fingerprint
 * @returns {boolean}
 */
function isDuplicate(fingerprint) {
  const expiry = _dedupMap.get(fingerprint);
  if (expiry && Date.now() < expiry) return true;

  _dedupMap.set(fingerprint, Date.now() + DEDUP_WINDOW_MS);

  // Purge périodique pour éviter la croissance mémoire non bornée
  if (_dedupMap.size > 5000) {
    const now = Date.now();
    for (const [k, v] of _dedupMap) {
      if (v < now) _dedupMap.delete(k);
    }
  }
  return false;
}

// ─── TCP probe ────────────────────────────────────────────────────────────────

/**
 * Sonde un port TCP unique sur un hôte.
 * ECONNREFUSED = hôte actif (port fermé mais machine joignable).
 *
 * @param {string} host
 * @param {number} port
 * @param {number} timeoutMs
 * @returns {Promise<boolean>}
 */
function probePort(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let alive = false;

    sock.setNoDelay(true);
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => { alive = true; sock.destroy(); });
    sock.on('timeout', () => sock.destroy());
    sock.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') alive = true; // hôte actif, port fermé
      sock.destroy();
    });
    sock.on('close', () => resolve(alive));
    sock.connect(port, host);
  });
}

/**
 * Sonde tous les ports de PROBE_PORTS en parallèle sur un hôte.
 * Retourne la liste des ports qui ont répondu.
 *
 * @param {string} host
 * @param {number[]} ports
 * @param {number} timeoutMs
 * @returns {Promise<number[]>}
 */
async function scanOpenPorts(host, ports, timeoutMs) {
  const results = await Promise.all(
    ports.map(async (port) => ({ port, open: await probePort(host, port, timeoutMs) }))
  );
  return results.filter((r) => r.open).map((r) => r.port);
}

// ─── Table ARP — Règle 1 ──────────────────────────────────────────────────────

/**
 * Décode la table ARP du système d'exploitation.
 * Retourne une liste de { ip, mac } pour tous les hôtes actifs connus de l'OS.
 *
 * Formats supportés :
 *   Windows : `arp -a`   → "  192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic"
 *   Linux   : `/proc/net/arp` → colonnes séparées par des espaces
 *
 * @returns {Promise<Array<{ ip: string, mac: string }>>}
 */
async function readArpTable() {
  const platform = os.platform();
  const entries = [];

  try {
    if (platform === 'win32') {
      const { stdout } = await execAsync('arp -a', { timeout: 6000 });
      // Regex : IP address puis Physical Address (format Windows avec tirets)
      const lineRe = /^\s+([\d.]+)\s+([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\s+/im;
      for (const line of stdout.split('\n')) {
        const m = lineRe.exec(line);
        if (!m) continue;
        const mac = m[2].replace(/-/g, ':').toLowerCase();
        // Exclure les adresses de diffusion et les entrées invalides
        if (mac === 'ff:ff:ff:ff:ff:ff' || mac === '00:00:00:00:00:00') continue;
        entries.push({ ip: m[1].trim(), mac });
      }
    } else {
      // Linux : /proc/net/arp — colonnes : IP HW_type Flags HW_address Mask Device
      const { stdout } = await execAsync('cat /proc/net/arp', { timeout: 5000 });
      for (const line of stdout.split('\n').slice(1)) { // sauter l'en-tête
        const parts = line.trim().split(/\s+/);
        if (parts.length < 4) continue;
        const mac = parts[3].toLowerCase();
        if (mac === '00:00:00:00:00:00' || mac === 'ff:ff:ff:ff:ff:ff') continue;
        // Ne garder que les entrées complètes (flag 0x2 = ATF_COM)
        if (parts[2] !== '0x2') continue;
        entries.push({ ip: parts[0], mac });
      }
    }
  } catch (err) {
    console.error('[net-scanner] Lecture table ARP échouée :', err.message);
  }

  return entries;
}

/**
 * Effectue un balayage ping de tous les hôtes du sous-réseau pour peupler
 * le cache ARP de l'OS, puis lit la table ARP.
 *
 * Le ping est best-effort : les erreurs sont ignorées silencieusement.
 * C'est la lecture ARP qui est la source de vérité.
 *
 * @param {string[]} subnets  Liste de CIDRs /24
 * @returns {Promise<Array<{ ip: string, mac: string }>>}
 */
async function arpSweep(subnets) {
  const allHosts = subnets.flatMap(expandSubnet24);
  const platform = os.platform();

  const pingCmd = platform === 'win32'
    ? (h) => `ping -n 1 -w 500 ${h}`
    : (h) => `ping -c 1 -W 1 ${h}`;

  // Lancement en parallèle — on ignore les échecs (hôtes hors ligne)
  await Promise.allSettled(
    allHosts.map((h) => execAsync(pingCmd(h), { timeout: 2000 }).catch(() => {}))
  );

  return readArpTable();
}

// ─── Helpers réseau ───────────────────────────────────────────────────────────

/**
 * Étend un bloc /24 en 254 adresses hôtes.
 * Seuls les sous-réseaux /24 sont supportés (scanner léger).
 *
 * @param {string} cidr  ex. "192.168.1.0/24"
 * @returns {string[]}
 */
function expandSubnet24(cidr) {
  const [base] = cidr.split('/');
  const parts = base.split('.').map(Number);
  if (parts.length !== 4) return [];
  const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
  return Array.from({ length: 254 }, (_, i) => `${prefix}.${i + 1}`);
}

/**
 * Résolution DNS inverse best-effort d'une adresse IP.
 * @param {string} ip
 * @returns {Promise<string>} hostname ou ip en cas d'échec
 */
async function reverseLookup(ip) {
  try {
    const platform = os.platform();
    const cmd = platform === 'win32' ? `nslookup ${ip}` : `host ${ip}`;
    const { stdout } = await execAsync(cmd, { timeout: 3000 });
    const match = platform === 'win32'
      ? /Name:\s+(\S+)/i.exec(stdout)
      : /domain name pointer (\S+)\.$/im.exec(stdout);
    return match ? match[1] : ip;
  } catch (_) {
    return ip;
  }
}

// ─── RÈGLE 1 — Base de données des appareils connus ──────────────────────────

/**
 * Vérifie si une adresse MAC est enregistrée dans known_devices.
 * @param {string} mac  Format normalisé minuscule avec deux-points (aa:bb:cc:dd:ee:ff)
 * @returns {Promise<boolean>}
 */
async function isMacKnown(mac) {
  const [rows] = await pool.query(
    'SELECT 1 FROM known_devices WHERE mac_address = ? LIMIT 1',
    [mac]
  );
  return Array.isArray(rows) && rows.length > 0;
}

/**
 * Enregistre ou met à jour un appareil dans known_devices.
 * Upsert par MAC : si l'adresse MAC existe déjà, on met à jour ip_address et last_seen.
 *
 * @param {{ mac: string, ip: string }} device
 * @returns {Promise<void>}
 */
async function upsertDevice({ mac, ip }) {
  await pool.query(
    `INSERT INTO known_devices (id, mac_address, ip_address, trusted, first_seen, last_seen)
     VALUES (?, ?, ?, 0, NOW(3), NOW(3))
     ON DUPLICATE KEY UPDATE
       ip_address = VALUES(ip_address),
       last_seen  = NOW(3)`,
    [uuidv4(), mac, ip]
  );
}

// ─── RÈGLE 3 — Surveillance du trafic sortant ────────────────────────────────

/**
 * Snapshot précédent pour le calcul du delta de trafic.
 * @type {{ bytes: number, capturedAt: number }|null}
 */
let _prevTrafficSnapshot = null;

/**
 * Lit le total des octets sortants cumulés sur toutes les interfaces réseau actives.
 *
 * Windows : PowerShell Get-NetAdapterStatistics (propriété SentBytes)
 * Linux   : /proc/net/dev (colonne tx_bytes, colonne 9, hors loopback)
 *
 * @returns {Promise<number|null>}  Nombre d'octets ou null si non disponible
 */
async function getOutboundBytes() {
  const platform = os.platform();

  try {
    if (platform === 'win32') {
      const ps = `(Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Measure-Object -Property SentBytes -Sum).Sum`;
      const { stdout } = await execAsync(
        `powershell -NonInteractive -NoProfile -Command "${ps}"`,
        { timeout: 10000 }
      );
      const val = parseFloat(stdout.trim());
      return isNaN(val) ? null : val;
    } else {
      const { stdout } = await execAsync('cat /proc/net/dev', { timeout: 5000 });
      let total = 0;
      // Format : "  eth0: rx_bytes ... tx_bytes (col 9)"
      for (const line of stdout.split('\n').slice(2)) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 10) continue;
        const iface = parts[0].replace(':', '');
        if (iface === 'lo') continue; // Exclure loopback
        total += parseInt(parts[9], 10) || 0;
      }
      return total;
    }
  } catch (err) {
    console.error('[net-scanner] Lecture compteurs trafic échouée :', err.message);
    return null;
  }
}

/**
 * Vérifie si le volume de trafic sortant dépasse le seuil dans la fenêtre de 10 min.
 * Met à jour le snapshot si nécessaire.
 * Retourne un objet de résultat si l'alerte est déclenchée, null sinon.
 *
 * @returns {Promise<{ deltaGB: number, windowMs: number }|null>}
 */
async function checkTrafficVolume() {
  const currentBytes = await getOutboundBytes();
  if (currentBytes === null) return null;

  const now = Date.now();

  if (_prevTrafficSnapshot) {
    const { bytes: prevBytes, capturedAt } = _prevTrafficSnapshot;
    const windowMs   = now - capturedAt;
    const deltaBytes = currentBytes - prevBytes;
    const deltaGB    = deltaBytes / (1024 ** 3);

    // Fenêtre de 10 minutes et seuil dépassé
    if (windowMs <= 10 * 60 * 1000 && deltaGB >= TRAFFIC_THRESHOLD_GB) {
      // Mise à jour du snapshot même en cas d'alerte (évite les alertes en boucle)
      _prevTrafficSnapshot = { bytes: currentBytes, capturedAt: now };
      return { deltaGB, windowMs };
    }
  }

  // Mettre à jour uniquement si les octets augmentent (évite les faux positifs au redémarrage)
  if (!_prevTrafficSnapshot || currentBytes >= _prevTrafficSnapshot.bytes) {
    _prevTrafficSnapshot = { bytes: currentBytes, capturedAt: now };
  }

  return null;
}

// ─── RÈGLE 4 — Détection de scan de ports ────────────────────────────────────

/**
 * Fenêtre glissante : source IP → liste de { port, ts }.
 * Permet de détecter plusieurs ports sondés depuis la même source en peu de temps.
 * @type {Map<string, Array<{ port: number, ts: number }>>}
 */
const _portScanTracker = new Map();

/**
 * Lit les connexions TCP établies via netstat.
 * Retourne les paires (adresse source externe → port de destination local).
 *
 * @returns {Promise<Array<{ srcIp: string, dstPort: number }>>}
 */
async function getInboundConnections() {
  const platform = os.platform();
  const connections = [];

  try {
    const cmd = platform === 'win32' ? 'netstat -n -p TCP' : 'netstat -tn';
    const { stdout } = await execAsync(cmd, { timeout: 8000 });

    // Format Windows/Linux : "Proto  LocalAddr:Port  ForeignAddr:Port  State"
    // On cherche : LocalIP:LocalPort   ForeignIP:ForeignPort   ESTABLISHED
    const re = /\b([\d.]+):(\d+)\s+([\d.]+):(\d+)\s+ESTABLISHED/i;

    for (const line of stdout.split('\n')) {
      const m = re.exec(line);
      if (!m) continue;

      const dstPort = parseInt(m[2], 10);
      const srcIp   = m[3];

      // Exclure les connexions locales (loopback)
      if (srcIp === '127.0.0.1' || srcIp === '::1' || srcIp === '0.0.0.0') continue;
      connections.push({ srcIp, dstPort });
    }
  } catch (err) {
    console.error('[net-scanner] Lecture netstat échouée :', err.message);
  }

  return connections;
}

/**
 * Injecte de nouvelles connexions dans le tracker à fenêtre glissante.
 * Retourne les adresses IP qui ont sondé plus de PORT_SCAN_THRESHOLD ports distincts
 * dans les PORT_SCAN_WINDOW_MS dernières millisecondes.
 *
 * @param {Array<{ srcIp: string, dstPort: number }>} connections
 * @returns {Array<{ srcIp: string, uniquePorts: number[] }>}
 */
function detectPortScans(connections) {
  const now    = Date.now();
  const cutoff = now - PORT_SCAN_WINDOW_MS;
  const scanners = [];

  // Enregistrer les nouvelles observations
  for (const { srcIp, dstPort } of connections) {
    if (!_portScanTracker.has(srcIp)) {
      _portScanTracker.set(srcIp, []);
    }
    _portScanTracker.get(srcIp).push({ port: dstPort, ts: now });
  }

  // Analyser chaque IP connue
  for (const [srcIp, obs] of _portScanTracker) {
    // Purger les observations hors fenêtre
    const fresh = obs.filter((o) => o.ts >= cutoff);

    if (fresh.length === 0) {
      _portScanTracker.delete(srcIp);
      continue;
    }

    _portScanTracker.set(srcIp, fresh);

    const uniquePorts = [...new Set(fresh.map((o) => o.port))];
    if (uniquePorts.length >= PORT_SCAN_THRESHOLD) {
      scanners.push({ srcIp, uniquePorts });
    }
  }

  // Purge globale si le tracker devient trop grand
  if (_portScanTracker.size > 5000) {
    for (const [k, v] of _portScanTracker) {
      if (v.every((o) => o.ts < cutoff)) _portScanTracker.delete(k);
    }
  }

  return scanners;
}

// ─── Cycle de détection principal ────────────────────────────────────────────

/**
 * Exécute un cycle complet de détection couvrant les 4 règles.
 *
 * Ordre d'exécution :
 *   1. Règle 4 (scan de ports)  — indépendant, très rapide, via netstat
 *   2. Règle 3 (trafic sortant) — indépendant, via compteurs OS
 *   3. Règles 1 & 2 (ARP sweep) — dépendantes du balayage réseau (plus lent)
 *
 * @param {import('socket.io').Server} [io]
 */
async function runDetectionCycle(io) {
  const subnets = (process.env.NET_SCAN_SUBNETS || '192.168.1.0/24')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  console.log(`[net-scanner] Cycle de détection démarré — sous-réseaux : ${subnets.join(', ')}`);

  // ── RÈGLE 4 : Détection de scan de ports ─────────────────────────────────
  const connections  = await getInboundConnections();
  const portScanners = detectPortScans(connections);

  for (const { srcIp, uniquePorts } of portScanners) {
    const fp = `portscan:${srcIp}`;
    if (isDuplicate(fp)) continue;

    console.warn(`[net-scanner] RÈGLE 4 — Scan de ports : ${srcIp} (${uniquePorts.length} ports distincts)`);

    createIncident({
      source: 'SYSTEM',
      category: 'intrusion_attempt',
      severity: 'critical',
      title: `Scan de ports détecté depuis ${srcIp}`,
      description:
        `Plus de ${uniquePorts.length} ports distincts ont été sondés depuis l'adresse IP ${srcIp} ` +
        `en moins de ${PORT_SCAN_WINDOW_MS / 1000} secondes.\n\n` +
        `Ports sondés : ${uniquePorts.slice(0, 30).join(', ')}` +
        `${uniquePorts.length > 30 ? ` … et ${uniquePorts.length - 30} autres` : ''}.\n\n` +
        `Action recommandée (NIST SP 800-61) : isolation immédiate de la source, ` +
        `analyse des journaux de connexion, vérification de l'intégrité des systèmes cibles.`,
      ip: srcIp,
      metadata: {
        rule: 4,
        norm: 'NIST CSF DE.CM-1 / ISO 27001 A.13.1.1',
        source_ip: srcIp,
        unique_port_count: uniquePorts.length,
        unique_ports: uniquePorts,
        window_ms: PORT_SCAN_WINDOW_MS,
        threshold: PORT_SCAN_THRESHOLD,
      },
      io,
    }).catch((err) => console.error('[net-scanner] Règle 4 — createIncident échoué :', err));
  }

  // ── RÈGLE 3 : Volume de trafic sortant anormal ───────────────────────────
  const trafficAlert = await checkTrafficVolume();

  if (trafficAlert) {
    const { deltaGB, windowMs } = trafficAlert;
    const fp = `traffic:${Math.floor(Date.now() / 60000)}`; // une alerte par minute max
    if (!isDuplicate(fp)) {
      console.warn(`[net-scanner] RÈGLE 3 — Trafic sortant anormal : ${deltaGB.toFixed(2)} GB en ${(windowMs / 60000).toFixed(1)} min`);

      createIncident({
        source: 'SYSTEM',
        category: 'data_leak',
        severity: 'critical',
        title: `Volume de données sortantes anormal : ${deltaGB.toFixed(2)}GB`,
        description:
          `${deltaGB.toFixed(2)} GB de données ont été émis vers l'extérieur en ` +
          `${(windowMs / 60000).toFixed(1)} minutes (seuil configuré : ${TRAFFIC_THRESHOLD_GB} GB).\n\n` +
          `Ce volume dépasse le seuil de détection d'exfiltration de données défini par la politique de sécurité.\n\n` +
          `Action requise (Loi 18-07 / ISO 27035) : isolation du système source, ` +
          `identification des flux suspects, notification ANPDP sous 72h si des données personnelles sont impliquées.`,
        metadata: {
          rule: 3,
          norm: 'NIST CSF DE.CM-1 / ISO 27001 A.12.4.1 / Loi 18-07',
          delta_bytes: Math.round(deltaGB * (1024 ** 3)),
          delta_gb: parseFloat(deltaGB.toFixed(4)),
          window_ms: windowMs,
          window_min: parseFloat((windowMs / 60000).toFixed(2)),
          threshold_gb: TRAFFIC_THRESHOLD_GB,
        },
        io,
      }).catch((err) => console.error('[net-scanner] Règle 3 — createIncident échoué :', err));
    }
  }

  // ── RÈGLES 1 & 2 : Balayage ARP + vérification des appareils/ports ───────
  let arpEntries = [];
  try {
    arpEntries = await arpSweep(subnets);
  } catch (err) {
    console.error('[net-scanner] Balayage ARP échoué :', err.message);
  }

  for (const { ip, mac } of arpEntries) {
    // ── RÈGLE 1 : Appareil inconnu (MAC absent de known_devices) ────────────
    let known = false;
    try {
      known = await isMacKnown(mac);
    } catch (err) {
      console.error(`[net-scanner] Vérification DB échouée pour ${mac} :`, err.message);
      continue;
    }

    if (!known) {
      // Enregistrer immédiatement l'appareil pour éviter les duplicatas dans ce cycle
      await upsertDevice({ mac, ip }).catch((err) =>
        console.error(`[net-scanner] upsertDevice échoué pour ${mac} :`, err.message)
      );

      const fp = `unknown-device:${mac}`;
      if (!isDuplicate(fp)) {
        console.warn(`[net-scanner] RÈGLE 1 — Appareil inconnu : MAC=${mac} IP=${ip}`);

        createIncident({
          source: 'SYSTEM',
          category: 'suspicious_activity',
          severity: 'critical',
          title: 'Appareil non répertorié détecté sur le réseau',
          description:
            `Un appareil avec l'adresse MAC ${mac} (IP : ${ip}) a été détecté sur le réseau local ` +
            `mais n'est pas répertorié dans la base de données known_devices.\n\n` +
            `Sous-réseaux analysés : ${subnets.join(', ')}.\n\n` +
            `Action requise (ISO 27001 A.8.1.1) : identifier le propriétaire de l'appareil, ` +
            `valider son autorisation d'accès ou bloquer l'adresse MAC au niveau du commutateur réseau.`,
          ip,
          machine_id: mac,
          metadata: {
            rule: 1,
            norm: 'NIST CSF ID.AM-1 / ISO 27001 A.8.1.1',
            mac_address: mac,
            ip_address: ip,
            subnets,
          },
          io,
        }).catch((err) => console.error('[net-scanner] Règle 1 — createIncident échoué :', err));
      }
    } else {
      // Mettre à jour last_seen même pour les appareils connus
      upsertDevice({ mac, ip }).catch(() => {});
    }

    // ── RÈGLE 2 : Port anormal ouvert ────────────────────────────────────────
    let openPorts = [];
    try {
      openPorts = await scanOpenPorts(ip, PROBE_PORTS, PROBE_TIMEOUT_MS);
    } catch (err) {
      console.error(`[net-scanner] Scan de ports échoué pour ${ip} :`, err.message);
      continue;
    }

    for (const port of openPorts) {
      if (ALLOWED_PORTS.has(port)) continue; // Port autorisé — aucune alerte

      const fp = `open-port:${ip}:${port}`;
      if (isDuplicate(fp)) continue;

      // Résolution DNS inverse best-effort
      const hostname = await reverseLookup(ip);

      console.warn(`[net-scanner] RÈGLE 2 — Port anormal : TCP/${port} sur ${hostname} (${ip})`);

      createIncident({
        source: 'SYSTEM',
        category: 'suspicious_activity',
        severity: 'high',
        title: `Port inhabituel ouvert : ${port} sur ${hostname}`,
        description:
          `Le port TCP ${port} est ouvert et accessible sur l'hôte ${hostname} (IP : ${ip}, MAC : ${mac}).\n\n` +
          `Ce port ne figure pas dans la liste des ports autorisés par la politique réseau ` +
          `([${[...ALLOWED_PORTS].join(', ')}]).\n\n` +
          `Action requise (ISO 27001 A.13.1.3) : vérifier si ce service est légitime, ` +
          `le désactiver ou appliquer un filtrage au pare-feu si non justifié.`,
        ip,
        machine_id: mac,
        metadata: {
          rule: 2,
          norm: 'NIST CSF PR.AC-5 / ISO 27001 A.13.1.3',
          ip_address: ip,
          mac_address: mac,
          hostname,
          open_port: port,
          allowed_ports: [...ALLOWED_PORTS],
        },
        io,
      }).catch((err) => console.error('[net-scanner] Règle 2 — createIncident échoué :', err));
    }
  }

  console.log(`[net-scanner] Cycle de détection terminé — ${arpEntries.length} hôte(s) analysé(s)`);
}

// ─── API publique ─────────────────────────────────────────────────────────────

/** Handle du setInterval actif (null si arrêté) */
let _scannerHandle = null;

/**
 * Démarre le scanner réseau Guardian.
 *
 * Exécute un premier cycle immédiatement (baseline), puis répète
 * toutes les NET_SCAN_INTERVAL_MS millisecondes.
 *
 * Aucun incident n'est levé si AUTO_DETECT_SCANNER_ENABLED n'est pas 'true' ;
 * ce démarrage est contrôlé par NET_SCAN_ENABLED dans index.js.
 *
 * @param {import('socket.io').Server} [io]
 */
function startNetworkScanner(io) {
  if (_scannerHandle) {
    console.warn('[net-scanner] Déjà en cours — appel startNetworkScanner() ignoré');
    return;
  }

  console.log(
    `[net-scanner] Démarrage — ` +
    `intervalle : ${SCAN_INTERVAL_MS}ms | ` +
    `sous-réseaux : ${process.env.NET_SCAN_SUBNETS || '192.168.1.0/24'} | ` +
    `seuil trafic : ${TRAFFIC_THRESHOLD_GB} GB | ` +
    `seuil scan : ${PORT_SCAN_THRESHOLD} ports / ${PORT_SCAN_WINDOW_MS / 1000}s`
  );

  // Premier cycle immédiat (sans attendre le premier intervalle)
  runDetectionCycle(io).catch((err) =>
    console.error('[net-scanner] Cycle initial échoué :', err)
  );

  // Planification des cycles suivants
  _scannerHandle = setInterval(() => {
    runDetectionCycle(io).catch((err) =>
      console.error('[net-scanner] Cycle échoué :', err)
    );
  }, SCAN_INTERVAL_MS);
}

/**
 * Arrête le scanner réseau et libère le timer.
 */
function stopNetworkScanner() {
  if (_scannerHandle) {
    clearInterval(_scannerHandle);
    _scannerHandle = null;
    console.log('[net-scanner] Scanner arrêté.');
  }
}

// ─── Manuel : vérification des ports ouverts sur un hôte précis ──────────────

/**
 * Scanne tous les PROBE_PORTS sur une adresse IP donnée (par défaut : l'IP du serveur)
 * et retourne les résultats.
 *
 * - Crée des incidents (Règle 2) pour chaque port anormal trouvé.
 * - Émet `scan:port-check:done` via Socket.IO avec le résumé.
 *
 * Appelé par : POST /api/auto-detect/port-check
 *
 * @param {string} [targetIp]             IP à analyser (défaut : IP locale du serveur)
 * @param {import('socket.io').Server} [io]
 * @returns {Promise<{
 *   target_ip:        string,
 *   scanned:          number,
 *   open:             number[],
 *   abnormal:         number[],
 *   incidents_created: number
 * }>}
 */
async function runLocalPortCheck(targetIp, io) {
  // Détermine l'IP cible — utilise l'IP non-loopback du serveur par défaut
  let resolvedIp = targetIp;
  if (!resolvedIp) {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
      for (const addr of ifaces[name]) {
        if (!addr.internal && addr.family === 'IPv4') {
          resolvedIp = addr.address;
          break;
        }
      }
      if (resolvedIp) break;
    }
    resolvedIp = resolvedIp || '127.0.0.1';
  }

  console.log(`[net-scanner] Vérification manuelle des ports sur ${resolvedIp}`);

  let openPorts = [];
  try {
    openPorts = await scanOpenPorts(resolvedIp, PROBE_PORTS, PROBE_TIMEOUT_MS);
  } catch (err) {
    console.error(`[net-scanner] Scan manuel échoué sur ${resolvedIp} :`, err.message);
  }

  const abnormalPorts = openPorts.filter((p) => !ALLOWED_PORTS.has(p));
  let incidentsCreated = 0;

  for (const port of abnormalPorts) {
    const fp = `open-port:${resolvedIp}:${port}:manual`;
    // Pas de déduplication stricte pour les vérifications manuelles — on force always
    _dedupMap.delete(`open-port:${resolvedIp}:${port}`); // reset dedup pour forcer l'incident

    const hostname = await reverseLookup(resolvedIp);
    try {
      await createIncident({
        source: 'SYSTEM',
        category: 'suspicious_activity',
        severity: 'high',
        title: `[Vérif. manuelle] Port inhabituel ouvert : ${port} sur ${hostname}`,
        description:
          `Vérification manuelle déclenchée depuis le tableau de bord.\n\n` +
          `Le port TCP ${port} est ouvert sur ${hostname} (${resolvedIp}).\n` +
          `Ce port ne figure pas dans la liste des ports autorisés ([${[...ALLOWED_PORTS].join(', ')}]).\n\n` +
          `Action requise (ISO 27001 A.13.1.3) : vérifier si ce service est légitime, ` +
          `le désactiver ou appliquer un filtrage au pare-feu si non justifié.`,
        ip: resolvedIp,
        metadata: {
          rule: 2,
          manual_check: true,
          norm: 'NIST CSF PR.AC-5 / ISO 27001 A.13.1.3',
          ip_address: resolvedIp,
          hostname,
          open_port: port,
          allowed_ports: [...ALLOWED_PORTS],
        },
        io,
      });
      incidentsCreated++;
    } catch (err) {
      console.error(`[net-scanner] Règle 2 manuelle — createIncident échoué (port ${port}) :`, err);
    }
  }

  const result = {
    target_ip:         resolvedIp,
    scanned:           PROBE_PORTS.length,
    open:              openPorts,
    abnormal:          abnormalPorts,
    incidents_created: incidentsCreated,
  };

  if (io) {
    io.to('admins').emit('scan:port-check:done', {
      ...result,
      ts: new Date().toISOString(),
    });
  }

  console.log(
    `[net-scanner] Vérification manuelle terminée — ` +
    `${openPorts.length} port(s) ouverts, ${abnormalPorts.length} anormaux, ` +
    `${incidentsCreated} incident(s) créé(s).`
  );

  return result;
}

module.exports = { startNetworkScanner, stopNetworkScanner, runLocalPortCheck };
