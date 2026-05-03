const pool = require('../db/pool');

const ASSIGNABLE_ROLES = ['it_analyst', 'it', 'it_manager', 'admin', 'dpo'];

function buildRoleOrderSql(column = 'u.role') {
  return `FIELD(${column}, 'it_analyst', 'it', 'it_manager', 'admin', 'dpo')`;
}

async function listAssignableUsers(conn = pool) {
  const [rows] = await conn.query(
    `SELECT u.id,
            u.name,
            u.email,
            u.department,
            u.role,
            u.manager_user_id,
            m.name AS manager_name,
            m.email AS manager_email,
            m.role AS manager_role
       FROM users u
       LEFT JOIN users m ON m.id = u.manager_user_id
      WHERE u.role IN (?, ?, ?, ?, ?)
      ORDER BY ${buildRoleOrderSql()}, u.name ASC`,
    ASSIGNABLE_ROLES
  );

  return rows;
}

async function getAssignableUserById(conn = pool, userId) {
  const [rows] = await conn.query(
    `SELECT u.id,
            u.name,
            u.email,
            u.department,
            u.role,
            u.manager_user_id,
            m.name AS manager_name,
            m.email AS manager_email,
            m.role AS manager_role
       FROM users u
       LEFT JOIN users m ON m.id = u.manager_user_id
      WHERE u.id = ?
        AND u.role IN (?, ?, ?, ?, ?)
      LIMIT 1`,
    [userId, ...ASSIGNABLE_ROLES]
  );

  return rows[0] || null;
}

async function resolveEscalationTarget(conn = pool, currentAssigneeId) {
  if (currentAssigneeId) {
    const currentAssignee = await getAssignableUserById(conn, currentAssigneeId);
    if (currentAssignee?.manager_user_id) {
      const manager = await getAssignableUserById(conn, currentAssignee.manager_user_id);
      if (manager) {
        return manager;
      }
    }
  }

  const [rows] = await conn.query(
    `SELECT id, name, email, department, role, manager_user_id
       FROM users
      WHERE role IN ('it_manager', 'admin', 'dpo')
        AND (? IS NULL OR id <> ?)
      ORDER BY FIELD(role, 'it_manager', 'admin', 'dpo'), name ASC
      LIMIT 1`,
    [currentAssigneeId || null, currentAssigneeId || null]
  );

  return rows[0] || null;
}

module.exports = {
  ASSIGNABLE_ROLES,
  listAssignableUsers,
  getAssignableUserById,
  resolveEscalationTarget,
};