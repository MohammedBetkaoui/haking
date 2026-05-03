const crypto = require('crypto');

/**
 * Create a SHA-256 hash of an incident record for integrity proof.
 */
function hashIncident({ id, timestamp, category, description }) {
  const data = `${id}|${timestamp}|${category}|${description || ''}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Create a chained hash for audit log entries.
 * previousHash links entries like a mini-blockchain.
 */
function hashAuditEntry({ incidentId, action, newValue, createdAt, previousHash }) {
  const data = `${incidentId}|${action}|${newValue || ''}|${createdAt}|${previousHash || ''}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = { hashIncident, hashAuditEntry };
