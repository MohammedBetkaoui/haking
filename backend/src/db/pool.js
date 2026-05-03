const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:               process.env.DB_HOST || 'localhost',
  user:               process.env.DB_USER || 'root',
  password:           process.env.DB_PASS || '',
  database:           process.env.DB_NAME || 'guardian_db',
  waitForConnections: true,
  connectionLimit:    parseInt(process.env.DB_POOL_SIZE || '30', 10),
  queueLimit:         0,
  enableKeepAlive:    true,
  keepAliveInitialDelay: 10000,
  timezone:           '+00:00',
});

module.exports = pool;

