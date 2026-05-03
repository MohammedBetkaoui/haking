const pool = require('./pool');

const DEFAULT_DIRECTORY_USERS = [
  {
    id: 'f18edaa5-30b6-4a80-acde-6d3afec7e001',
    name: 'Nadia Rahal',
    email: 'dpo@guardian.local',
    department: 'Compliance',
    role: 'dpo',
    managerUserId: null,
  },
  {
    id: 'f18edaa5-30b6-4a80-acde-6d3afec7e002',
    name: 'Sami Merabet',
    email: 'soc.manager@guardian.local',
    department: 'SOC',
    role: 'it_manager',
    managerUserId: 'f18edaa5-30b6-4a80-acde-6d3afec7e001',
  },
  {
    id: 'f18edaa5-30b6-4a80-acde-6d3afec7e003',
    name: 'Lina Benyahia',
    email: 'soc.n1@guardian.local',
    department: 'SOC',
    role: 'it_analyst',
    managerUserId: 'f18edaa5-30b6-4a80-acde-6d3afec7e002',
  },
  {
    id: 'f18edaa5-30b6-4a80-acde-6d3afec7e004',
    name: 'Yacine Benaissa',
    email: 'soc.n2@guardian.local',
    department: 'SOC',
    role: 'it',
    managerUserId: 'f18edaa5-30b6-4a80-acde-6d3afec7e002',
  },
];

const TABLE_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
    id          CHAR(36) PRIMARY KEY,
    name        VARCHAR(120) NOT NULL,
    email       VARCHAR(255) NOT NULL UNIQUE,
    department  VARCHAR(120) NULL,
    role        VARCHAR(32) NOT NULL DEFAULT 'employee',
    manager_user_id CHAR(36) NULL,
    created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ,CONSTRAINT fk_users_manager
      FOREIGN KEY (manager_user_id) REFERENCES users(id)
      ON UPDATE CASCADE ON DELETE SET NULL,
    INDEX idx_users_role (role),
    INDEX idx_users_manager (manager_user_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS incidents (
    id                 CHAR(36) PRIMARY KEY,
    user_id            CHAR(36) NULL,
    anonymous          BOOLEAN NOT NULL DEFAULT FALSE,
    machine_id         VARCHAR(255) NULL,
    ip_address         VARCHAR(255) NULL,
    category           VARCHAR(64) NOT NULL,
    severity           VARCHAR(32) NOT NULL DEFAULT 'medium',
    title              VARCHAR(200) NOT NULL,
    description        TEXT NULL,
    source             VARCHAR(32) NOT NULL DEFAULT 'USER',
    status             VARCHAR(32) NOT NULL DEFAULT 'open',
    workflow_phase     VARCHAR(32) NOT NULL DEFAULT 'assess',
    workflow_state     VARCHAR(32) NOT NULL DEFAULT 'active',
    assigned_to        CHAR(36) NULL,
    assigned_team      VARCHAR(120) NULL,
    sla_due_at         DATETIME(3) NULL,
    sla_warning_at     DATETIME(3) NULL,
    sla_breached_at    DATETIME(3) NULL,
    escalation_level   INT NOT NULL DEFAULT 0,
    last_transition_at DATETIME(3) NULL,
    acknowledged_at    DATETIME(3) NULL,
    resolved_at        DATETIME(3) NULL,
    closed_at          DATETIME(3) NULL,
    learned_at         DATETIME(3) NULL,
    evidence_hash      VARCHAR(255) NULL,
    metadata           JSON NULL,
    created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_incidents_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON UPDATE CASCADE ON DELETE SET NULL,
    CONSTRAINT fk_incidents_assigned_to
      FOREIGN KEY (assigned_to) REFERENCES users(id)
      ON UPDATE CASCADE ON DELETE SET NULL,
    INDEX idx_incidents_status (status),
    INDEX idx_incidents_severity (severity),
    INDEX idx_incidents_phase_due (workflow_phase, sla_due_at),
    INDEX idx_incidents_created_at (created_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS audit_logs (
    id            CHAR(36) PRIMARY KEY,
    incident_id   CHAR(36) NOT NULL,
    actor_id      CHAR(36) NULL,
    actor_role    VARCHAR(32) NULL,
    action        VARCHAR(64) NOT NULL,
    old_value     TEXT NULL,
    new_value     TEXT NULL,
    note          TEXT NULL,
    ip_address    VARCHAR(255) NULL,
    log_hash      VARCHAR(255) NULL,
    created_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_audit_logs_incident
      FOREIGN KEY (incident_id) REFERENCES incidents(id)
      ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_audit_logs_actor
      FOREIGN KEY (actor_id) REFERENCES users(id)
      ON UPDATE CASCADE ON DELETE SET NULL,
    INDEX idx_audit_logs_incident_created (incident_id, created_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS checklist_items (
    id           CHAR(36) PRIMARY KEY,
    incident_id  CHAR(36) NOT NULL,
    step         INT NOT NULL,
    label        VARCHAR(500) NOT NULL,
    completed    BOOLEAN NOT NULL DEFAULT FALSE,
    completed_at DATETIME(3) NULL,
    created_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_checklist_items_incident
      FOREIGN KEY (incident_id) REFERENCES incidents(id)
      ON UPDATE CASCADE ON DELETE CASCADE,
    UNIQUE KEY uq_checklist_items_incident_step (incident_id, step)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS workflow_events (
    id            CHAR(36) PRIMARY KEY,
    incident_id   CHAR(36) NOT NULL,
    phase         VARCHAR(32) NOT NULL,
    event_type    VARCHAR(32) NOT NULL,
    actor_id      CHAR(36) NULL,
    actor_role    VARCHAR(32) NULL,
    from_state    VARCHAR(32) NULL,
    to_state      VARCHAR(32) NULL,
    note          TEXT NULL,
    due_at        DATETIME(3) NULL,
    warning_at    DATETIME(3) NULL,
    breached_at   DATETIME(3) NULL,
    escalation_level INT NOT NULL DEFAULT 0,
    created_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_workflow_events_incident
      FOREIGN KEY (incident_id) REFERENCES incidents(id)
      ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_workflow_events_actor
      FOREIGN KEY (actor_id) REFERENCES users(id)
      ON UPDATE CASCADE ON DELETE SET NULL,
    INDEX idx_workflow_events_incident_created (incident_id, created_at),
    INDEX idx_workflow_events_phase (phase, event_type)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS notification_deliveries (
    id             CHAR(36) PRIMARY KEY,
    incident_id    CHAR(36) NULL,
    channel        VARCHAR(32) NOT NULL,
    target         VARCHAR(255) NULL,
    severity       VARCHAR(32) NULL,
    event_type     VARCHAR(64) NOT NULL,
    status         VARCHAR(32) NOT NULL DEFAULT 'pending',
    response_code  INT NULL,
    error_message  TEXT NULL,
    payload        JSON NULL,
    delivered_at   DATETIME(3) NULL,
    created_at     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_notification_deliveries_incident
      FOREIGN KEY (incident_id) REFERENCES incidents(id)
      ON UPDATE CASCADE ON DELETE SET NULL,
    INDEX idx_notification_deliveries_incident_created (incident_id, created_at),
    INDEX idx_notification_deliveries_status (status, channel)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS monthly_reports (
    id             CHAR(36) PRIMARY KEY,
    report_month   DATE NOT NULL,
    status         VARCHAR(32) NOT NULL DEFAULT 'pending',
    storage_path   VARCHAR(500) NULL,
    generated_by   CHAR(36) NULL,
    summary        JSON NULL,
    generated_at   DATETIME(3) NULL,
    created_at     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_monthly_reports_generated_by
      FOREIGN KEY (generated_by) REFERENCES users(id)
      ON UPDATE CASCADE ON DELETE SET NULL,
    UNIQUE KEY uq_monthly_reports_month (report_month)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  /* ── Module de Détection Automatique — NIST CSF / ISO 27001 ── */
  `CREATE TABLE IF NOT EXISTS known_devices (
    id           CHAR(36) PRIMARY KEY,
    mac_address  VARCHAR(17) NOT NULL,
    ip_address   VARCHAR(45) NULL,
    hostname     VARCHAR(255) NULL,
    name         VARCHAR(255) NULL,
    trusted      BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    created_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uq_known_devices_mac (mac_address),
    INDEX idx_known_devices_trusted (trusted),
    INDEX idx_known_devices_last_seen (last_seen)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
];

const USER_COLUMNS = [
  ['manager_user_id', 'ALTER TABLE users ADD COLUMN manager_user_id CHAR(36) NULL AFTER role']
];

const USER_INDEXES = [
  ['idx_users_role', 'CREATE INDEX idx_users_role ON users (role)'],
  ['idx_users_manager', 'CREATE INDEX idx_users_manager ON users (manager_user_id)']
];

const INCIDENT_COLUMNS = [
  ['source', "ALTER TABLE incidents ADD COLUMN source VARCHAR(32) NOT NULL DEFAULT 'USER' AFTER description"],
  ['workflow_phase', "ALTER TABLE incidents ADD COLUMN workflow_phase VARCHAR(32) NOT NULL DEFAULT 'assess' AFTER status"],
  ['workflow_state', "ALTER TABLE incidents ADD COLUMN workflow_state VARCHAR(32) NOT NULL DEFAULT 'active' AFTER workflow_phase"],
  ['assigned_to', 'ALTER TABLE incidents ADD COLUMN assigned_to CHAR(36) NULL AFTER workflow_state'],
  ['assigned_team', 'ALTER TABLE incidents ADD COLUMN assigned_team VARCHAR(120) NULL AFTER assigned_to'],
  ['sla_due_at', 'ALTER TABLE incidents ADD COLUMN sla_due_at DATETIME(3) NULL AFTER assigned_team'],
  ['sla_warning_at', 'ALTER TABLE incidents ADD COLUMN sla_warning_at DATETIME(3) NULL AFTER sla_due_at'],
  ['sla_breached_at', 'ALTER TABLE incidents ADD COLUMN sla_breached_at DATETIME(3) NULL AFTER sla_warning_at'],
  ['escalation_level', 'ALTER TABLE incidents ADD COLUMN escalation_level INT NOT NULL DEFAULT 0 AFTER sla_breached_at'],
  ['last_transition_at', 'ALTER TABLE incidents ADD COLUMN last_transition_at DATETIME(3) NULL AFTER escalation_level'],
  ['acknowledged_at', 'ALTER TABLE incidents ADD COLUMN acknowledged_at DATETIME(3) NULL AFTER last_transition_at'],
  ['resolved_at', 'ALTER TABLE incidents ADD COLUMN resolved_at DATETIME(3) NULL AFTER acknowledged_at'],
  ['closed_at', 'ALTER TABLE incidents ADD COLUMN closed_at DATETIME(3) NULL AFTER resolved_at'],
  ['learned_at', 'ALTER TABLE incidents ADD COLUMN learned_at DATETIME(3) NULL AFTER closed_at']
];

const INCIDENT_INDEXES = [
  ['idx_incidents_status', 'CREATE INDEX idx_incidents_status ON incidents (status)'],
  ['idx_incidents_severity', 'CREATE INDEX idx_incidents_severity ON incidents (severity)'],
  ['idx_incidents_phase_due', 'CREATE INDEX idx_incidents_phase_due ON incidents (workflow_phase, sla_due_at)'],
  ['idx_incidents_created_at', 'CREATE INDEX idx_incidents_created_at ON incidents (created_at)']
];

const TRIGGER_STATEMENTS = [
  'DROP TRIGGER IF EXISTS incidents_before_update_set_updated_at',
  `CREATE TRIGGER incidents_before_update_set_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    BEGIN
      SET NEW.updated_at = CURRENT_TIMESTAMP(3);
    END`,
  'DROP TRIGGER IF EXISTS monthly_reports_before_update_set_updated_at',
  `CREATE TRIGGER monthly_reports_before_update_set_updated_at
    BEFORE UPDATE ON monthly_reports
    FOR EACH ROW
    BEGIN
      SET NEW.updated_at = CURRENT_TIMESTAMP(3);
    END`,
  'DROP TRIGGER IF EXISTS audit_logs_prevent_update',
  `CREATE TRIGGER audit_logs_prevent_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    BEGIN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only';
    END`,
  'DROP TRIGGER IF EXISTS audit_logs_prevent_delete',
  `CREATE TRIGGER audit_logs_prevent_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
    BEGIN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only';
    END`,
  'DROP TRIGGER IF EXISTS workflow_events_prevent_update',
  `CREATE TRIGGER workflow_events_prevent_update
    BEFORE UPDATE ON workflow_events
    FOR EACH ROW
    BEGIN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'workflow_events is append-only';
    END`,
  'DROP TRIGGER IF EXISTS workflow_events_prevent_delete',
  `CREATE TRIGGER workflow_events_prevent_delete
    BEFORE DELETE ON workflow_events
    FOR EACH ROW
    BEGIN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'workflow_events is append-only';
    END`
];

/**
 * @param {string} tableName
 * @param {string} columnName
 */
async function columnExists(tableName, columnName) {
  const [rows] = await pool.query(
    `SELECT 1
       FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = ?
        AND COLUMN_NAME = ?
      LIMIT 1`,
    [tableName, columnName]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/**
 * @param {string} tableName
 * @param {string} indexName
 */
async function indexExists(tableName, indexName) {
  const [rows] = await pool.query(
    `SELECT 1
       FROM INFORMATION_SCHEMA.STATISTICS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = ?
        AND INDEX_NAME = ?
      LIMIT 1`,
    [tableName, indexName]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/**
 * @param {string} tableName
 * @param {string} constraintName
 */
async function constraintExists(tableName, constraintName) {
  const [rows] = await pool.query(
    `SELECT 1
       FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = ?
        AND CONSTRAINT_NAME = ?
      LIMIT 1`,
    [tableName, constraintName]
  );

  return Array.isArray(rows) && rows.length > 0;
}

async function ensureUserColumns() {
  for (const [columnName, statement] of USER_COLUMNS) {
    if (!(await columnExists('users', columnName))) {
      await pool.query(statement);
    }
  }
}

async function ensureUserIndexes() {
  for (const [indexName, statement] of USER_INDEXES) {
    if (!(await indexExists('users', indexName))) {
      await pool.query(statement);
    }
  }
}

async function ensureUserConstraints() {
  if (!(await constraintExists('users', 'fk_users_manager'))) {
    await pool.query(
      `ALTER TABLE users
         ADD CONSTRAINT fk_users_manager
         FOREIGN KEY (manager_user_id) REFERENCES users(id)
         ON UPDATE CASCADE ON DELETE SET NULL`
    );
  }
}

async function ensureIncidentColumns() {
  for (const [columnName, statement] of INCIDENT_COLUMNS) {
    if (!(await columnExists('incidents', columnName))) {
      await pool.query(statement);
    }
  }
}

async function ensureIncidentIndexes() {
  for (const [indexName, statement] of INCIDENT_INDEXES) {
    if (!(await indexExists('incidents', indexName))) {
      await pool.query(statement);
    }
  }
}

async function seedDefaultUsers() {
  for (const user of DEFAULT_DIRECTORY_USERS) {
    await pool.query(
      `INSERT IGNORE INTO users (id, name, email, department, role, manager_user_id)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [user.id, user.name, user.email, user.department, user.role, user.managerUserId]
    );
  }
}

/**
 * @param {string[]} statements
 */
async function runStatements(statements) {
  for (const statement of statements) {
    await pool.query(statement);
  }
}

async function migrate() {
  try {
    await pool.query('SELECT 1');

    await runStatements(TABLE_STATEMENTS);
    await ensureUserColumns();
    await ensureUserIndexes();
    await ensureUserConstraints();
    await ensureIncidentColumns();
    await ensureIncidentIndexes();
    await seedDefaultUsers();
    await runStatements(TRIGGER_STATEMENTS);

    console.log('✅ MySQL schema ready for Guardian workflow engine');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('❌ MySQL migration failed:', message);
    throw err;
  }
}

module.exports = migrate;

if (require.main === module) {
  migrate()
    .then(() => pool.end())
    .catch(async (err) => {
      try {
        await pool.end();
      } catch (_) {
        // Ignore pool shutdown failures while surfacing the migration error.
      }

      console.error(err);
      process.exitCode = 1;
    });
}

