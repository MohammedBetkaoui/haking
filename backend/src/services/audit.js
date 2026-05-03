const { v4: uuidv4 } = require('uuid');

const { hashAuditEntry } = require('../utils/hash');

async function appendAuditLog(conn, {
  incidentId,
  actorId = null,
  actorRole = null,
  action,
  oldValue = null,
  newValue = null,
  note = null,
  ipAddress = null,
  createdAt = new Date(),
}) {
  const auditId = uuidv4();
  const auditTimestamp = createdAt instanceof Date ? createdAt : new Date(createdAt);

  const [lastLogRows] = await conn.query(
    'SELECT log_hash FROM audit_logs WHERE incident_id = ? ORDER BY created_at DESC, id DESC LIMIT 1',
    [incidentId]
  );

  const previousHash = lastLogRows[0]?.log_hash || null;
  const auditHash = hashAuditEntry({
    incidentId,
    action,
    newValue: typeof newValue === 'string' ? newValue : JSON.stringify(newValue),
    createdAt: auditTimestamp.toISOString(),
    previousHash,
  });

  await conn.query(
    `INSERT INTO audit_logs
       (id, incident_id, actor_id, actor_role, action, old_value, new_value, note, ip_address, log_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      auditId,
      incidentId,
      actorId,
      actorRole,
      action,
      oldValue,
      typeof newValue === 'string' ? newValue : JSON.stringify(newValue),
      note,
      ipAddress,
      auditHash,
      auditTimestamp,
    ]
  );

  return { id: auditId, logHash: auditHash, previousHash, createdAt: auditTimestamp };
}

module.exports = { appendAuditLog };