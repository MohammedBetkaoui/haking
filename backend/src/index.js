require('dotenv').config();
const http = require('http');
const express = require('express');
const cors = require('cors');
const helmetModule = require('helmet');
const morgan = require('morgan');
const { Server } = require('socket.io');
const rateLimitModule = require('express-rate-limit');
const cron = require('node-cron');

/** @type {any} */
const helmet = helmetModule.default || helmetModule;
/** @type {any} */
const rateLimit = rateLimitModule.rateLimit || rateLimitModule.default || rateLimitModule;

const migrate = require('./db/migrate');
const reportRouter = require('./routes/report');
const incidentsRouter = require('./routes/incidents');
const usersRouter = require('./routes/users');
const reportsRouter = require('./routes/reports');
const cyberAgentRouter = require('./routes/cyberAgent');
const deviceDetailsRouter = require('./routes/deviceDetails');
const { runSlaMonitor } = require('./jobs/sla-monitor');
const { runMonthlyReportJob } = require('./jobs/monthly-reports');
const { startNetworkScanner, startLogWatcher, siemRouter } = require('./services/auto-detection.service');
const { startNetworkScanner: startGuardianScanner } = require('./auto-detection/network-scanner.service');
const { startLogWatcher: startGuardianLogWatcher } = require('./auto-detection/log-watcher.service');
const siemWebhookRouter = require('./auto-detection/siem-webhook.controller');

const app = express();
const server = http.createServer(app);

// ---- Socket.io ----4
const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST'],
  },
});

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('join:admins', () => {
    socket.join('admins');
    console.log(`Socket ${socket.id} joined admins room`);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

app.set('io', io);

// ---- Middleware ----
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(morgan('dev'));
app.use(express.json({ limit: '1mb' }));

// Rate limit report endpoint to prevent spam
const reportLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many reports, please slow down.' },
});

// ---- Routes ----
app.use('/api/report', reportLimiter, reportRouter);
app.use('/api/incidents', incidentsRouter);
app.use('/api/users', usersRouter);
app.use('/api/reports', reportsRouter);
app.use('/api/cyber-agent', cyberAgentRouter);
app.use('/api/auto-detect', siemRouter);
app.use('/api/siem', siemWebhookRouter);
app.use('/api/device-details', deviceDetailsRouter);

app.get('/', (_, res) => res.json({ name: 'Guardian API', version: '1.0.0', status: 'running', docs: '/health' }));
app.get('/health', (_, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

// ---- Start ----
const PORT = process.env.PORT || 4000;

function scheduleJobs() {
  const timezone = process.env.SCHEDULER_TIMEZONE || 'UTC';
  const reportExpression = process.env.REPORT_CRON || '0 5 1 * *';

  // SLA monitor: use fast setInterval (default 10 s) instead of 1-minute cron
  // so SLA warnings and breaches are surfaced almost immediately.
  const slaIntervalMs = parseInt(process.env.SLA_INTERVAL_MS || '10000', 10);
  let _slaRunning = false;
  setInterval(() => {
    if (_slaRunning) return; // skip tick if previous run is still in progress
    _slaRunning = true;
    runSlaMonitor({ io })
      .catch((err) => console.error('SLA monitor failed:', err))
      .finally(() => { _slaRunning = false; });
  }, slaIntervalMs);

  cron.schedule(reportExpression, () => {
    runMonthlyReportJob().catch((err) => console.error('Monthly report job failed:', err));
  }, { timezone });

  if (process.env.SLA_RUN_ON_START === 'true') {
    runSlaMonitor({ io }).catch((err) => console.error('Initial SLA monitor failed:', err));
  }

  if (process.env.REPORT_RUN_ON_START === 'true') {
    runMonthlyReportJob().catch((err) => console.error('Initial monthly report job failed:', err));
  }

  if (process.env.AUTO_DETECT_SCANNER_ENABLED === 'true') {
    startNetworkScanner(io);
  }

  if (process.env.AUTO_DETECT_LOG_WATCHER_ENABLED === 'true') {
    startLogWatcher(io);
  }

  if (process.env.NET_SCAN_ENABLED === 'true') {
    startGuardianScanner(io);
  }

  if (process.env.GUARDIAN_LOG_WATCHER_ENABLED === 'true') {
    startGuardianLogWatcher(io);
  }
}

(async () => {
  await migrate();
  scheduleJobs();
  server.listen(PORT, () => {
    console.log(`\n🛡️  Guardian Backend running on http://localhost:${PORT}\n`);
  });
})();
