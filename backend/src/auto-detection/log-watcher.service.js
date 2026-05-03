'use strict';

/**
 * log-watcher.service.js
 * ──────────────────────
 * GUARDIAN — Surveillance des journaux système (sans intervention humaine)
 *
 * Normes appliquées :
 *   ISO 27001 A.12.4  — Journalisation et surveillance
 *   NIST CSF DE.CM-3  — Surveillance des activités du personnel
 *   NIST SP 800-61    — Guide de réponse aux incidents
 *
 * 6 règles de corrélation sur Windows Event Log (source: 'SYSTEM') :
 *
 * ┌──────┬──────────────────────────────────────────┬────────┬──────────┐
 * │ Règle│ Condition                                │ Event  │ Sévérité │
 * ├──────┼──────────────────────────────────────────┼────────┼──────────┤
 * │  W1  │ >5 échecs connexion / 2 min / même compte│ 4625   │ HIGH     │
 * │  W2  │ Admin connecté entre 22h et 6h           │ 4624   │ HIGH     │
 * │  W3  │ Nouveau service non whitelisté installé  │ 7045   │ CRITICAL │
 * │  W4  │ Antivirus désactivé                      │ 5001   │ CRITICAL │
 * │  W5  │ Périphérique USB de stockage connecté    │ 6416   │ HIGH     │
 * │  W6  │ Élévation de privilèges (non-admin)      │ 4672   │ CRITICAL │
 * └──────┴──────────────────────────────────────────┴────────┴──────────┘
 *
 * Variables d'environnement (toutes optionnelles) :
 *   GUARDIAN_LOG_WATCHER_ENABLED      'true' pour activer (défaut: false)
 *   GUARDIAN_LOG_WATCHER_INTERVAL_MS  Intervalle entre cycles en ms (défaut: 60000)
 *   GUARDIAN_ADMIN_ACCOUNTS           Comptes admin légitimes, virgule-séparé
 *                                     (défaut: Administrator,Administrateur,admin)
 *   GUARDIAN_SERVICE_WHITELIST        Services autorisés supplémentaires, virgule-séparé
 *   GUARDIAN_OFFICE_START_H           Début heures bureau 0-23 (défaut: 6)
 *   GUARDIAN_OFFICE_END_H             Fin heures bureau 0-23  (défaut: 22)
 *   GUARDIAN_BRUTE_THRESHOLD          Seuil d'échecs connexion (défaut: 5)
 *   GUARDIAN_BRUTE_WINDOW_MS          Fenêtre glissante brute force en ms (défaut: 120000)
 *   GUARDIAN_LOG_DEDUP_WINDOW_MS      Fenêtre de déduplication en ms (défaut: 600000)
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const os = require('os');

const { createIncident } = require('../services/auto-detection.service');

const execAsync = promisify(exec);

// ─── Configuration ────────────────────────────────────────────────────────────

const INTERVAL_MS     = parseInt(process.env.GUARDIAN_LOG_WATCHER_INTERVAL_MS || '60000',  10);
const OFFICE_START_H  = parseInt(process.env.GUARDIAN_OFFICE_START_H           || '6',      10);
const OFFICE_END_H    = parseInt(process.env.GUARDIAN_OFFICE_END_H             || '22',     10);
const BRUTE_THRESHOLD = parseInt(process.env.GUARDIAN_BRUTE_THRESHOLD          || '5',      10);
const BRUTE_WINDOW_MS = parseInt(process.env.GUARDIAN_BRUTE_WINDOW_MS          || '120000', 10);
const DEDUP_WINDOW_MS = parseInt(process.env.GUARDIAN_LOG_DEDUP_WINDOW_MS      || '600000', 10);

/**
 * Comptes techniques Windows dont les privilèges élevés sont normaux.
 * Ces comptes sont exclus des règles W2, W6.
 */
const SYSTEM_ACCOUNTS = new Set([
  'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE',
  'DWM-1', 'DWM-2', 'DWM-3',
  'UMFD-0', 'UMFD-1', 'UMFD-2', 'UMFD-3',
  'ANONYMOUS LOGON', 'IUSR', '-', '',
]);

/**
 * Comptes administrateurs légitimes (configurables).
 * La connexion hors horaires et l'élévation de droits pour ces comptes
 * est considérée normale et n'est PAS alertée.
 */
const ADMIN_ACCOUNTS = new Set(
  (process.env.GUARDIAN_ADMIN_ACCOUNTS || 'Administrator,Administrateur,admin')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
);

/**
 * Whitelist des services Windows légitimes.
 * Tout service installé absent de cette liste déclenche la règle W3.
 * Étendu via GUARDIAN_SERVICE_WHITELIST (env var, virgule-séparé).
 * Référence : ISO 27001 A.12.6.2
 */
const SERVICE_WHITELIST = new Set([
  // Noyau Windows
  'wuauserv', 'spooler', 'bits', 'winrm', 'windefend', 'mpsvc', 'wscsvc',
  'eventlog', 'plugplay', 'dnscache', 'dhcp', 'netlogon', 'lanmanserver',
  'lanmanworkstation', 'lmhosts', 'server', 'workstation', 'rpcss', 'dcom',
  'cryptsvc', 'trustedinstaller', 'msiserver', 'schedule', 'themes',
  'audiosrv', 'audioendpointbuilder', 'nsi', 'iphlpsvc', 'nlasvc',
  'netprofm', 'dot3svc', 'wlansvc', 'bfe', 'mpssvc', 'sharedaccess',
  'fdrespub', 'fntcache', 'gpsvc', 'samss', 'seclogon',
  'sens', 'ssdpsrv', 'stisvc', 'swprv', 'trkwks', 'vss', 'wbengine',
  'wecsvc', 'wudf', 'winspool', 'termservice', 'sessionenv', 'umrdpservice',
  'w3svc', 'was', 'snmptrap', 'msftpsvc', 'tlntsvr',
  // Windows Defender / MDE / EDR
  'mssecflt', 'sysmondrv', 'sense', 'wdfilter', 'wdndrv', 'wdboot',
  'mssense', 'csagent', 'csdevicecontrol', 'windumpdrv', 'cldflt',
  // Outils d'administration courants
  'sshd', 'openssh', 'npcap', 'winpcap', 'vmtools', 'vmhgfs', 'vmci',
  'vmxnet3', 'vmusbmouse', 'vmrawdsk',
  // Entrées personnalisées via env
  ...(process.env.GUARDIAN_SERVICE_WHITELIST || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
]);

/**
 * Privilèges Windows indiquant une élévation critique (règle W6).
 * Référence : Microsoft Security Documentation / MITRE ATT&CK T1548
 */
const DANGEROUS_PRIVILEGES = [
  'SeDebugPrivilege',           // Débogage de processus quelconques
  'SeTcbPrivilege',             // Agir en tant que partie du système d'exploitation
  'SeLoadDriverPrivilege',      // Charger / décharger un pilote kernel
  'SeCreateTokenPrivilege',     // Créer un jeton d'accès arbitraire
  'SeTakeOwnershipPrivilege',   // Prendre possession de n'importe quel objet
  'SeBackupPrivilege',          // Contournement des ACL en lecture
  'SeRestorePrivilege',         // Contournement des ACL en écriture
  'SeImpersonatePrivilege',     // Usurper l'identité d'un client
  'SeAssignPrimaryTokenPrivilege', // Remplacer le token d'un processus
];

// ─── Déduplication ────────────────────────────────────────────────────────────

/** @type {Map<string, number>} fingerprint → timestamp d'expiration */
const _dedupMap = new Map();

/**
 * Vérifie si un événement est un doublon dans la fenêtre configurée.
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

// ─── État de corrélation W1 — Fenêtre glissante brute force ──────────────────

/**
 * Horodatages des échecs de connexion par compte (epoch ms).
 * @type {Map<string, number[]>}
 */
const _bruteMap = new Map();

/**
 * Enregistre un échec et retourne true si le seuil est dépassé dans la fenêtre.
 * @param {string} account  Nom du compte cible (normalisé minuscule)
 * @param {number} ts       Timestamp de l'événement (epoch ms)
 * @returns {boolean}
 */
function recordFailedLogin(account, ts) {
  const key = account.toLowerCase();
  if (!_bruteMap.has(key)) _bruteMap.set(key, []);

  const times  = _bruteMap.get(key);
  times.push(ts);

  const cutoff = ts - BRUTE_WINDOW_MS;
  const fresh  = times.filter((t) => t >= cutoff);
  _bruteMap.set(key, fresh);

  return fresh.length > BRUTE_THRESHOLD;
}

// ─── Helper PowerShell / Get-WinEvent ────────────────────────────────────────

/**
 * Interroge un journal d'événements Windows via Get-WinEvent.
 * Retourne un tableau structuré `{ TimeCreated, Id, Data }`.
 *
 * Sécurité : seuls des valeurs provenant de constantes internes (event IDs,
 * noms de journaux) et d'un objet Date sont interpolées — aucun input utilisateur.
 *
 * @param {string}   logName    Nom du journal (ex. 'Security', 'System')
 * @param {number[]} eventIds   Event IDs à récupérer
 * @param {Date}     since      Borne temporelle inférieure
 * @param {number}  [maxEvents] Limite de résultats (défaut: 200)
 * @returns {Promise<Array<{ TimeCreated: string, Id: number, Data: Record<string,string> }>>}
 */
async function queryWinEvents(logName, eventIds, since, maxEvents = 200) {
  // Le module est exclusivement Windows
  if (os.platform() !== 'win32') return [];

  // Timestamp ISO 8601 issu uniquement de Date() — pas d'input utilisateur
  const sinceStr = since.toISOString();
  const idList   = eventIds.join(',');

  // Script PowerShell inline : extrait TimeCreated, Id et tous les champs EventData en JSON
  const ps = [
    `$ev = Get-WinEvent -FilterHashtable @{LogName='${logName}'; Id=${idList}; StartTime='${sinceStr}'} -ErrorAction SilentlyContinue | Select-Object -First ${maxEvents};`,
    `if (-not $ev) { Write-Output '[]'; exit }`,
    `$r = $ev | ForEach-Object { try {`,
    `  $x = [xml]$_.ToXml(); $d = @{};`,
    `  if ($x.Event.EventData.Data) { $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } } }`,
    `  [PSCustomObject]@{ TimeCreated=$_.TimeCreated.ToString('o'); Id=[int]$_.Id; Data=$d }`,
    `} catch {} };`,
    `$r | ConvertTo-Json -Compress -Depth 4`,
  ].join(' ');

  let stdout;
  try {
    ({ stdout } = await execAsync(
      `powershell -NonInteractive -NoProfile -Command "${ps.replace(/"/g, '\\"')}"`,
      { timeout: 15000 }
    ));
  } catch (_err) {
    // Permissions insuffisantes ou journal inexistant — dégradation silencieuse
    return [];
  }

  const raw = (stdout || '').trim();
  if (!raw || raw === 'null' || raw === '[]') return [];

  try {
    const parsed = JSON.parse(raw);
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    return arr.filter((e) => e && e.Id && e.TimeCreated);
  } catch (_err) {
    return [];
  }
}

// ─── RÈGLE W1 — Brute Force (Event ID 4625) ──────────────────────────────────

/**
 * Détecte les tentatives de brute force par corrélation temporelle.
 * Condition : plus de BRUTE_THRESHOLD échecs sur le même compte
 *             en moins de BRUTE_WINDOW_MS millisecondes.
 *
 * Référence : ISO 27001 A.9.4.2, NIST SP 800-61 §3.2.2
 *
 * @param {import('socket.io').Server} [io]
 * @param {Date} since
 */
async function checkBruteForce(io, since) {
  const events = await queryWinEvents('Security', [4625], since);

  for (const evt of events) {
    const account   = (evt.Data.TargetUserName    || evt.Data.SubjectUserName || 'inconnu').trim();
    const domain    = (evt.Data.TargetDomainName  || '').trim();
    const srcIp     = (evt.Data.IpAddress         || '').trim().replace('::ffff:', '');
    const logonType = (evt.Data.LogonType         || '?');
    const ts        = new Date(evt.TimeCreated).getTime();

    if (SYSTEM_ACCOUNTS.has(account.toUpperCase())) continue;

    const exceeded = recordFailedLogin(account, ts);
    if (!exceeded) continue;

    const fp = `w1:bruteforce:${account.toLowerCase()}:${Math.floor(ts / BRUTE_WINDOW_MS)}`;
    if (isDuplicate(fp)) continue;

    console.warn(`[log-watcher] W1 — Brute Force : compte="${account}" source=${srcIp || '?'}`);

    createIncident({
      source: 'SYSTEM',
      category: 'suspicious_activity',
      severity: 'high',
      title: `Brute force détecté sur le compte "${account}"`,
      description:
        `Plus de ${BRUTE_THRESHOLD} tentatives de connexion échouées ont été enregistrées ` +
        `sur le compte "${account}"${domain ? ` (domaine : ${domain})` : ''} en moins de ` +
        `${BRUTE_WINDOW_MS / 60000} minute(s) (Event ID 4625).\n\n` +
        `Adresse source : ${srcIp || 'inconnue'} | Type de connexion : ${logonType}\n\n` +
        `Action requise (ISO 27001 A.9.4.2 / NIST SP 800-61 §3.2.2) :\n` +
        `  • Vérifier la légitimité des tentatives\n` +
        `  • Verrouiller le compte si l'activité est malveillante\n` +
        `  • Bloquer l'IP source au niveau du pare-feu`,
      ip: srcIp || null,
      metadata: {
        rule: 'W1',
        norm: 'ISO 27001 A.9.4.2 / NIST CSF DE.CM-3 / MITRE T1110',
        account, domain, src_ip: srcIp, logon_type: logonType,
        brute_threshold: BRUTE_THRESHOLD,
        brute_window_ms: BRUTE_WINDOW_MS,
        event_id: 4625,
      },
      io,
    }).catch((err) => console.error('[log-watcher] W1 createIncident échoué :', err));
  }
}

// ─── RÈGLE W2 — Admin hors horaires (Event ID 4624) ──────────────────────────

/**
 * Détecte les connexions d'un compte administrateur hors des heures de bureau.
 * Condition : connexion d'un compte admin entre OFFICE_END_H et OFFICE_START_H.
 *
 * Référence : ISO 27001 A.9.1.1, NIST CSF PR.AC-1
 *
 * @param {import('socket.io').Server} [io]
 * @param {Date} since
 */
async function checkAfterHoursAdmin(io, since) {
  const events = await queryWinEvents('Security', [4624], since);

  for (const evt of events) {
    const account    = (evt.Data.TargetUserName      || '').trim();
    const domain     = (evt.Data.TargetDomainName    || '').trim();
    const logonType  = parseInt(evt.Data.LogonType   || '0', 10);
    const srcIp      = (evt.Data.IpAddress           || '').trim().replace('::ffff:', '');
    const eventTime  = new Date(evt.TimeCreated);
    const hour       = eventTime.getHours();

    // Ignorer les comptes système
    if (!account || SYSTEM_ACCOUNTS.has(account.toUpperCase())) continue;

    // Ignorer les connexions par lot et de service (types 4 et 5)
    if (logonType === 4 || logonType === 5) continue;

    // Détecter si le compte est administrateur (nom dans ADMIN_ACCOUNTS ou heuristique)
    const nameLower  = account.toLowerCase();
    const isAdmin    = ADMIN_ACCOUNTS.has(nameLower)
      || nameLower === 'administrator'
      || nameLower === 'administrateur'
      || nameLower.includes('admin');

    if (!isAdmin) continue;

    // Hors heures de bureau : avant OFFICE_START_H ou à partir de OFFICE_END_H
    const afterHours = hour < OFFICE_START_H || hour >= OFFICE_END_H;
    if (!afterHours) continue;

    const fp = `w2:admin-hours:${nameLower}:${eventTime.toDateString()}:${hour}`;
    if (isDuplicate(fp)) continue;

    const timeStr = eventTime.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    const dateStr = eventTime.toLocaleDateString('fr-FR');

    console.warn(`[log-watcher] W2 — Admin hors horaires : "${account}" à ${timeStr}`);

    createIncident({
      source: 'SYSTEM',
      category: 'suspicious_activity',
      severity: 'high',
      title: `Connexion admin hors horaires : "${account}" à ${timeStr}`,
      description:
        `Le compte administrateur "${account}"${domain ? ` (${domain})` : ''} ` +
        `s'est connecté à ${timeStr} le ${dateStr}, hors des heures de bureau ` +
        `autorisées (${OFFICE_START_H}h–${OFFICE_END_H}h).\n\n` +
        `Adresse source : ${srcIp || 'inconnue'} | Type de connexion : ${logonType} (Event ID 4624)\n\n` +
        `Action requise (ISO 27001 A.9.1.1) :\n` +
        `  • Contacter l'administrateur pour confirmer la légitimité de la connexion\n` +
        `  • Vérifier les commandes et fichiers accédés pendant la session\n` +
        `  • Consulter les journaux d'activité de la session`,
      ip: srcIp || null,
      metadata: {
        rule: 'W2',
        norm: 'ISO 27001 A.9.1.1 / NIST CSF PR.AC-1 / MITRE T1078',
        account, domain, src_ip: srcIp, logon_type: logonType,
        event_time: evt.TimeCreated, hour,
        office_start_h: OFFICE_START_H,
        office_end_h: OFFICE_END_H,
        event_id: 4624,
      },
      io,
    }).catch((err) => console.error('[log-watcher] W2 createIncident échoué :', err));
  }
}

// ─── RÈGLE W3 — Nouveau service installé (Event ID 7045) ─────────────────────

/**
 * Détecte l'installation d'un service Windows absent de la whitelist autorisée.
 * Condition : n'importe quand — tout service non whitelisté.
 *
 * Référence : ISO 27001 A.12.6.2, MITRE ATT&CK T1543.003
 *
 * @param {import('socket.io').Server} [io]
 * @param {Date} since
 */
async function checkNewService(io, since) {
  const events = await queryWinEvents('System', [7045], since, 50);

  for (const evt of events) {
    const serviceName = (evt.Data.ServiceName || '').trim();
    const imagePath   = (evt.Data.ImagePath   || '').trim();
    const serviceType = (evt.Data.ServiceType || '').trim();
    const startType   = (evt.Data.StartType   || '').trim();
    const accountName = (evt.Data.AccountName || '').trim();

    if (!serviceName) continue;

    // Vérification insensible à la casse
    if (SERVICE_WHITELIST.has(serviceName.toLowerCase())) continue;

    const fp = `w3:new-service:${serviceName.toLowerCase()}`;
    if (isDuplicate(fp)) continue;

    console.warn(`[log-watcher] W3 — Nouveau service non autorisé : "${serviceName}" → ${imagePath}`);

    createIncident({
      source: 'SYSTEM',
      category: 'suspicious_activity',
      severity: 'critical',
      title: `Nouveau service non autorisé installé : "${serviceName}"`,
      description:
        `Un nouveau service Windows "${serviceName}" a été installé sur le système ` +
        `et n'est pas répertorié dans la liste des services autorisés (Event ID 7045).\n\n` +
        `Chemin de l'exécutable : ${imagePath || 'inconnu'}\n` +
        `Type de service        : ${serviceType || 'inconnu'}\n` +
        `Type de démarrage      : ${startType || 'inconnu'}\n` +
        `Compte de service      : ${accountName || 'inconnu'}\n\n` +
        `Les malwares utilisent fréquemment des services Windows pour la persistance ` +
        `(MITRE ATT&CK T1543.003 — Create or Modify System Process).\n\n` +
        `Action requise (ISO 27001 A.12.6.2) :\n` +
        `  • Identifier la source et l'auteur de l'installation\n` +
        `  • Analyser l'exécutable avec un antivirus et un bac à sable\n` +
        `  • Arrêter et désactiver le service si non justifié`,
      metadata: {
        rule: 'W3',
        norm: 'ISO 27001 A.12.6.2 / NIST CSF PR.IP-1 / MITRE T1543.003',
        service_name: serviceName,
        image_path: imagePath,
        service_type: serviceType,
        start_type: startType,
        account: accountName,
        event_id: 7045,
      },
      io,
    }).catch((err) => console.error('[log-watcher] W3 createIncident échoué :', err));
  }
}

// ─── RÈGLE W4 — Antivirus désactivé (Event ID 5001) ──────────────────────────

/**
 * Détecte la désactivation de la protection en temps réel de Windows Defender.
 * Event ID 5001 : journal Microsoft-Windows-Windows Defender/Operational.
 * Condition : immédiat — chaque occurrence déclenche un incident.
 *
 * Référence : ISO 27001 A.12.2.1, NIST SP 800-61 §3.3
 *
 * @param {import('socket.io').Server} [io]
 * @param {Date} since
 */
async function checkAntivirusDisabled(io, since) {
  const events = await queryWinEvents(
    'Microsoft-Windows-Windows Defender/Operational',
    [5001],
    since,
    20
  );

  for (const evt of events) {
    const product   = (evt.Data.Product   || 'Windows Defender').trim();
    const reason    = (evt.Data.Reason    || evt.Data.ErrorCode || '').trim();
    const eventTime = new Date(evt.TimeCreated);
    const dateStr   = eventTime.toLocaleString('fr-FR');

    const fp = `w4:av-disabled:${Math.floor(eventTime.getTime() / 60000)}`;
    if (isDuplicate(fp)) continue;

    console.warn(`[log-watcher] W4 — Antivirus désactivé : ${product} à ${dateStr}`);

    createIncident({
      source: 'SYSTEM',
      category: 'suspicious_activity',
      severity: 'critical',
      title: `Antivirus désactivé : ${product}`,
      description:
        `La protection en temps réel de ${product} a été désactivée le ${dateStr} ` +
        `(Event ID 5001).\n\n` +
        `${reason ? `Raison / Code d'erreur : ${reason}\n\n` : ''}` +
        `La désactivation d'un antivirus est une technique classique précédant une attaque ` +
        `(ransomware, APT, Living-off-the-Land — MITRE T1562.001).\n\n` +
        `Action requise (ISO 27001 A.12.2.1 / NIST SP 800-61 §3.3) :\n` +
        `  • Réactiver immédiatement la protection en temps réel\n` +
        `  • Identifier le processus ou l'utilisateur ayant effectué l'action\n` +
        `  • Lancer un scan complet du système\n` +
        `  • Vérifier les processus en cours d'exécution pour des signes de compromission`,
      metadata: {
        rule: 'W4',
        norm: 'ISO 27001 A.12.2.1 / NIST CSF PR.AT-1 / MITRE T1562.001',
        product, reason,
        event_time: evt.TimeCreated,
        event_id: 5001,
      },
      io,
    }).catch((err) => console.error('[log-watcher] W4 createIncident échoué :', err));
  }
}

// ─── RÈGLE W5 — Périphérique USB / exfiltration (Event ID 6416) ──────────────

/**
 * Détecte la connexion d'un périphérique de stockage externe (clé USB, disque).
 * Event ID 6416 : "A new external device was recognized by the system".
 *
 * Note technique : Event 6416 signale la reconnaissance du périphérique.
 * Pour détecter les fichiers copiés (> 10 MB), activer l'audit "Object Access"
 * et corréler avec Event ID 4663 (Object Access — Write). Ce service émet
 * un incident dès la connexion du périphérique comme signal de risque d'exfiltration.
 *
 * Référence : ISO 27001 A.8.3.1, Loi 18-07
 *
 * @param {import('socket.io').Server} [io]
 * @param {Date} since
 */
async function checkUsbDevice(io, since) {
  const events = await queryWinEvents('Security', [6416], since, 50);

  // GUID de classe Windows identifiant les périphériques de stockage de masse
  const STORAGE_CLASS_GUIDS = new Set([
    '{4d36e967-e325-11ce-bfc1-08002be10318}', // DiskDrive
    '{4d36e96b-e325-11ce-bfc1-08002be10318}', // Keyboard (exclu en réalité — pour exhaustivité)
    '{36fc9e60-c465-11cf-8056-444553540000}', // USB
    '{88bae032-5a81-49f0-bc3d-a4ff138216d6}', // USB Storage
  ]);

  for (const evt of events) {
    const deviceId     = (evt.Data.DeviceId || evt.Data.DeviceInstanceId || '').trim();
    const deviceDesc   = (evt.Data.DeviceDescription || evt.Data.ClassName || '').trim();
    const classId      = (evt.Data.ClassId || '').trim().toLowerCase();
    const subjectUser  = (evt.Data.SubjectUserName   || '').trim();
    const subjectDomain= (evt.Data.SubjectDomainName || '').trim();

    if (!deviceId) continue;

    // Filtrer uniquement les périphériques de stockage
    const idLow  = deviceId.toLowerCase();
    const descLow= deviceDesc.toLowerCase();
    const isStorage =
      idLow.includes('usbstor') ||
      idLow.includes('disk')    ||
      descLow.includes('disk')  ||
      descLow.includes('usb')   ||
      descLow.includes('storage') ||
      STORAGE_CLASS_GUIDS.has(classId);

    if (!isStorage) continue;

    const fp = `w5:usb:${deviceId.slice(0, 80)}`;
    if (isDuplicate(fp)) continue;

    const isSystemUser = !subjectUser || SYSTEM_ACCOUNTS.has(subjectUser.toUpperCase());
    const userStr = isSystemUser
      ? 'un compte système'
      : `${subjectUser}${subjectDomain ? '@' + subjectDomain : ''}`;

    console.warn(`[log-watcher] W5 — USB connecté : ${deviceDesc || deviceId} (utilisateur : ${userStr})`);

    createIncident({
      source: 'SYSTEM',
      category: 'data_leak',
      severity: 'high',
      title: `Périphérique USB de stockage connecté par ${userStr}`,
      description:
        `Un périphérique USB de stockage a été connecté par ${userStr} (Event ID 6416).\n\n` +
        `Périphérique : ${deviceDesc || 'inconnu'}\n` +
        `Identifiant  : ${deviceId.slice(0, 120)}\n\n` +
        `Risque d'exfiltration de données (ISO 27001 A.8.3.1 / Loi 18-07).\n\n` +
        `Précision sur la détection des fichiers > 10 MB :\n` +
        `  Activer l'audit "Object Access" dans la politique de sécurité locale ` +
        `  et corréler avec Event ID 4663 (Write Access) pour une détection précise.\n\n` +
        `Action requise :\n` +
        `  • Vérifier si la connexion est autorisée par la politique BYOD\n` +
        `  • Inspecter les fichiers transférés\n` +
        `  • Appliquer une politique DLP si ce type de transfert doit être bloqué`,
      metadata: {
        rule: 'W5',
        norm: 'ISO 27001 A.8.3.1 / Loi 18-07 / MITRE T1052.001',
        device_id: deviceId.slice(0, 200),
        device_description: deviceDesc,
        class_id: classId,
        user: userStr,
        event_id: 6416,
      },
      io,
    }).catch((err) => console.error('[log-watcher] W5 createIncident échoué :', err));
  }
}

// ─── RÈGLE W6 — Élévation de privilèges (Event ID 4672) ──────────────────────

/**
 * Détecte l'attribution de privilèges système critiques à un compte non-administrateur.
 * Event ID 4672 : "Special privileges assigned to new logon".
 *
 * Référence : ISO 27001 A.9.2.3, MITRE ATT&CK T1548
 *
 * @param {import('socket.io').Server} [io]
 * @param {Date} since
 */
async function checkPrivilegeEscalation(io, since) {
  const events = await queryWinEvents('Security', [4672], since);

  for (const evt of events) {
    const account    = (evt.Data.SubjectUserName    || '').trim();
    const domain     = (evt.Data.SubjectDomainName  || '').trim();
    const privileges = (evt.Data.PrivilegeList      || '').trim();
    const logonId    = (evt.Data.SubjectLogonId     || '').trim();

    // Ignorer les comptes système — ils reçoivent toujours des privilèges élevés au démarrage
    if (!account || SYSTEM_ACCOUNTS.has(account.toUpperCase())) continue;

    // Ignorer les comptes administrateurs légitimes configurés
    const nameLower    = account.toLowerCase();
    const isKnownAdmin = ADMIN_ACCOUNTS.has(nameLower)
      || nameLower === 'administrator'
      || nameLower === 'administrateur';
    if (isKnownAdmin) continue;

    // Vérifier la présence de privilèges dangereux
    const matched = DANGEROUS_PRIVILEGES.filter((p) =>
      privileges.toLowerCase().includes(p.toLowerCase())
    );
    if (matched.length === 0) continue;

    const fp = `w6:privesc:${nameLower}:${logonId}`;
    if (isDuplicate(fp)) continue;

    console.warn(`[log-watcher] W6 — Élévation privilèges : "${account}" reçoit : ${matched.join(', ')}`);

    createIncident({
      source: 'SYSTEM',
      category: 'suspicious_activity',
      severity: 'critical',
      title: `Élévation de privilèges détectée : compte "${account}"`,
      description:
        `Le compte "${account}"${domain ? ` (${domain})` : ''} a reçu des privilèges ` +
        `système critiques sans être répertorié comme administrateur autorisé (Event ID 4672).\n\n` +
        `Privilèges critiques attribués :\n${matched.map((p) => `  • ${p}`).join('\n')}\n\n` +
        `Cette attribution peut indiquer :\n` +
        `  — Exploitation d'une vulnérabilité locale (LPE)\n` +
        `  — Abus de configuration ou de délégation\n` +
        `  — Mouvement latéral post-compromission (MITRE T1548)\n\n` +
        `Action requise (ISO 27001 A.9.2.3) :\n` +
        `  • Identifier l'origine de l'élévation (processus, script, CVE)\n` +
        `  • Révoquer les droits si non justifiés\n` +
        `  • Analyser les actions effectuées avec ces privilèges`,
      metadata: {
        rule: 'W6',
        norm: 'ISO 27001 A.9.2.3 / NIST CSF PR.AC-4 / MITRE T1548',
        account, domain,
        logon_id: logonId,
        matched_privileges: matched,
        raw_privileges: privileges.slice(0, 500),
        event_id: 4672,
      },
      io,
    }).catch((err) => console.error('[log-watcher] W6 createIncident échoué :', err));
  }
}

// ─── Cycle de surveillance principal ─────────────────────────────────────────

/** Borne temporelle du dernier cycle (utilisée pour Get-WinEvent StartTime) */
let _lastCheckAt = null;

/**
 * Exécute un cycle complet : les 6 règles sont interrogées en parallèle.
 * Sur Linux, ce module est no-op (utiliser auto-detection.service.js pour auth.log).
 *
 * @param {import('socket.io').Server} [io]
 */
async function runWatchCycle(io) {
  if (os.platform() !== 'win32') return;

  const since  = _lastCheckAt || new Date(Date.now() - INTERVAL_MS);
  _lastCheckAt = new Date();

  console.log(`[log-watcher] Cycle W1–W6 — depuis ${since.toISOString()}`);

  // Les 6 règles tournent en parallèle (journaux distincts, pas de race condition)
  const results = await Promise.allSettled([
    checkBruteForce(io, since),         // W1 — Security  4625
    checkAfterHoursAdmin(io, since),    // W2 — Security  4624
    checkNewService(io, since),         // W3 — System    7045
    checkAntivirusDisabled(io, since),  // W4 — Defender  5001
    checkUsbDevice(io, since),          // W5 — Security  6416
    checkPrivilegeEscalation(io, since),// W6 — Security  4672
  ]);

  // Journaliser les éventuelles erreurs internes (sans interrompre les autres règles)
  const labels = ['W1', 'W2', 'W3', 'W4', 'W5', 'W6'];
  for (let i = 0; i < results.length; i++) {
    if (results[i].status === 'rejected') {
      console.error(`[log-watcher] Règle ${labels[i]} échouée :`, results[i].reason);
    }
  }
}

// ─── API publique ─────────────────────────────────────────────────────────────

/** Handle du setInterval actif */
let _watcherHandle = null;

/**
 * Démarre le Guardian Log Watcher.
 * Windows uniquement — no-op sur Linux/macOS.
 *
 * @param {import('socket.io').Server} [io]
 */
function startLogWatcher(io) {
  if (_watcherHandle) {
    console.warn('[log-watcher] Déjà en cours — appel ignoré');
    return;
  }

  if (os.platform() !== 'win32') {
    console.log('[log-watcher] Plateforme non-Windows — Guardian Log Watcher désactivé.');
    return;
  }

  console.log(
    `[log-watcher] Démarrage Guardian Log Watcher W1–W6 — ` +
    `intervalle : ${INTERVAL_MS}ms | ` +
    `brute force : >${BRUTE_THRESHOLD} / ${BRUTE_WINDOW_MS / 1000}s | ` +
    `heures bureau : ${OFFICE_START_H}h–${OFFICE_END_H}h`
  );

  // Premier cycle immédiat (baseline)
  runWatchCycle(io).catch((err) =>
    console.error('[log-watcher] Cycle initial échoué :', err)
  );

  _watcherHandle = setInterval(() => {
    runWatchCycle(io).catch((err) =>
      console.error('[log-watcher] Cycle échoué :', err)
    );
  }, INTERVAL_MS);
}

/**
 * Arrête le Guardian Log Watcher et libère le timer.
 */
function stopLogWatcher() {
  if (_watcherHandle) {
    clearInterval(_watcherHandle);
    _watcherHandle = null;
    console.log('[log-watcher] Arrêté.');
  }
}

module.exports = { startLogWatcher, stopLogWatcher };
