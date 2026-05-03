const { v4: uuidv4 } = require('uuid');

// In-memory storage — data is lost on server restart
const incidents  = new Map();
const auditLogs  = new Map(); // key = incident_id → []
const checklists = new Map(); // key = incident_id → []

module.exports = { incidents, auditLogs, checklists, uuidv4 };
