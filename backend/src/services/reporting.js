const fs = require('fs');
const fsPromises = require('fs/promises');
const path = require('path');
const PDFDocument = require('pdfkit');
const { v4: uuidv4 } = require('uuid');

const pool = require('../db/pool');
const { notifyMonthlyReportGenerated } = require('./notifications');

function parseMonthInput(month) {
  if (!month) {
    return getPreviousMonthDate();
  }

  if (!/^\d{4}-\d{2}$/.test(month)) {
    throw new Error('Invalid month format. Expected YYYY-MM');
  }

  return new Date(`${month}-01T00:00:00.000Z`);
}

function getPreviousMonthDate(reference = new Date()) {
  return new Date(Date.UTC(reference.getUTCFullYear(), reference.getUTCMonth() - 1, 1, 0, 0, 0, 0));
}

function getMonthKey(date) {
  return date.toISOString().slice(0, 7);
}

function getMonthBounds(monthDate) {
  const start = new Date(Date.UTC(monthDate.getUTCFullYear(), monthDate.getUTCMonth(), 1, 0, 0, 0, 0));
  const end = new Date(Date.UTC(monthDate.getUTCFullYear(), monthDate.getUTCMonth() + 1, 1, 0, 0, 0, 0));
  return { start, end };
}

function getReportOutputDir() {
  return process.env.REPORT_OUTPUT_DIR || path.resolve(__dirname, '..', '..', 'generated-reports');
}

function normalizeJson(value, fallback) {
  if (value == null) {
    return fallback;
  }

  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch (_) {
      return fallback;
    }
  }

  return value;
}

async function fetchMonthlySummary(conn, monthDate) {
  const { start, end } = getMonthBounds(monthDate);
  const [byStatus] = await conn.query(
    `SELECT status, COUNT(*) AS count
       FROM incidents
      WHERE created_at >= ? AND created_at < ?
      GROUP BY status`,
    [start, end]
  );
  const [bySeverity] = await conn.query(
    `SELECT severity, COUNT(*) AS count
       FROM incidents
      WHERE created_at >= ? AND created_at < ?
      GROUP BY severity`,
    [start, end]
  );
  const [byCategory] = await conn.query(
    `SELECT category, COUNT(*) AS count
       FROM incidents
      WHERE created_at >= ? AND created_at < ?
      GROUP BY category
      ORDER BY count DESC`,
    [start, end]
  );
  const [[metrics]] = await conn.query(
    `SELECT
        COUNT(*) AS total_incidents,
        SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) AS resolved_incidents,
        SUM(CASE WHEN status <> 'closed' THEN 1 ELSE 0 END) AS ongoing_incidents,
        SUM(CASE WHEN escalation_level > 0 THEN 1 ELSE 0 END) AS escalated_incidents,
        SUM(CASE WHEN sla_breached_at IS NOT NULL THEN 1 ELSE 0 END) AS breached_incidents,
        AVG(CASE WHEN acknowledged_at IS NOT NULL THEN TIMESTAMPDIFF(MINUTE, created_at, acknowledged_at) END) AS avg_ack_minutes,
        AVG(CASE WHEN resolved_at IS NOT NULL THEN TIMESTAMPDIFF(MINUTE, created_at, resolved_at) END) AS avg_resolution_minutes
       FROM incidents
      WHERE created_at >= ? AND created_at < ?`,
    [start, end]
  );

  return {
    month: getMonthKey(monthDate),
    generated_at: new Date().toISOString(),
    total_incidents: Number(metrics.total_incidents || 0),
    resolved_incidents: Number(metrics.resolved_incidents || 0),
    ongoing_incidents: Number(metrics.ongoing_incidents || 0),
    escalated_incidents: Number(metrics.escalated_incidents || 0),
    breached_incidents: Number(metrics.breached_incidents || 0),
    avg_ack_minutes: metrics.avg_ack_minutes == null ? null : Number(metrics.avg_ack_minutes),
    avg_resolution_minutes: metrics.avg_resolution_minutes == null ? null : Number(metrics.avg_resolution_minutes),
    by_status: byStatus,
    by_severity: bySeverity,
    by_category: byCategory,
  };
}

function renderMonthlyReportPdf(filePath, summary) {
  return new Promise((resolve, reject) => {
    const document = new PDFDocument({ margin: 48, size: 'A4' });
    const stream = fs.createWriteStream(filePath);

    document.pipe(stream);

    document.fontSize(22).fillColor('#0f172a').text('Guardian Monthly Compliance Report', { align: 'left' });
    document.moveDown(0.4);
    document.fontSize(12).fillColor('#334155').text(`Report month: ${summary.month}`);
    document.text(`Generated at: ${summary.generated_at}`);
    document.moveDown();

    document.fontSize(16).fillColor('#111827').text('Executive Summary');
    document.moveDown(0.5);
    document.fontSize(11).fillColor('#1f2937');
    document.text(`Total incidents: ${summary.total_incidents}`);
    document.text(`Resolved incidents: ${summary.resolved_incidents}`);
    document.text(`Ongoing incidents: ${summary.ongoing_incidents}`);
    document.text(`Escalated incidents: ${summary.escalated_incidents}`);
    document.text(`SLA breaches: ${summary.breached_incidents}`);
    document.text(`Average acknowledgement time: ${summary.avg_ack_minutes == null ? 'n/a' : `${summary.avg_ack_minutes.toFixed(1)} minutes`}`);
    document.text(`Average resolution time: ${summary.avg_resolution_minutes == null ? 'n/a' : `${summary.avg_resolution_minutes.toFixed(1)} minutes`}`);

    document.moveDown();
    document.fontSize(16).fillColor('#111827').text('Breakdown By Severity');
    document.moveDown(0.3);
    summary.by_severity.forEach((row) => {
      document.fontSize(11).fillColor('#1f2937').text(`- ${row.severity}: ${row.count}`);
    });

    document.moveDown();
    document.fontSize(16).fillColor('#111827').text('Breakdown By Category');
    document.moveDown(0.3);
    summary.by_category.forEach((row) => {
      document.fontSize(11).fillColor('#1f2937').text(`- ${row.category}: ${row.count}`);
    });

    document.moveDown();
    document.fontSize(16).fillColor('#111827').text('Compliance Notes');
    document.moveDown(0.3);
    document.fontSize(11).fillColor('#1f2937');
    document.text('This report consolidates ISO 27035 workflow activity, SLA performance, and incident throughput for the selected month.');
    document.text('The document is generated automatically by Guardian and can be used as an audit-ready monthly summary.');

    document.end();

    stream.on('finish', resolve);
    stream.on('error', reject);
    document.on('error', reject);
  });
}

async function listMonthlyReports(limit = 12) {
  const [rows] = await pool.query(
    `SELECT mr.*, u.name AS generated_by_name
       FROM monthly_reports mr
       LEFT JOIN users u ON u.id = mr.generated_by
      ORDER BY mr.report_month DESC
      LIMIT ?`,
    [Number(limit)]
  );

  return rows.map((row) => ({
    ...row,
    summary: normalizeJson(row.summary, null),
  }));
}

async function getMonthlyReportById(id) {
  const [rows] = await pool.query(
    `SELECT mr.*, u.name AS generated_by_name
       FROM monthly_reports mr
       LEFT JOIN users u ON u.id = mr.generated_by
      WHERE mr.id = ?
      LIMIT 1`,
    [id]
  );

  if (!rows.length) {
    return null;
  }

  return {
    ...rows[0],
    summary: normalizeJson(rows[0].summary, null),
  };
}

async function generateMonthlyReport({ month, generatedBy = null, force = false } = {}) {
  const monthDate = parseMonthInput(month);
  const monthKey = getMonthKey(monthDate);
  const reportMonthValue = `${monthKey}-01`;
  const outputDirectory = getReportOutputDir();
  const outputPath = path.join(outputDirectory, `guardian-monthly-${monthKey}.pdf`);
  const conn = await pool.getConnection();

  try {
    const [existingRows] = await conn.query(
      'SELECT * FROM monthly_reports WHERE report_month = ? LIMIT 1',
      [reportMonthValue]
    );
    const existing = existingRows[0] || null;

    if (existing && existing.status === 'generated' && existing.storage_path && !force) {
      return {
        ...existing,
        summary: normalizeJson(existing.summary, null),
        reused: true,
      };
    }

    const summary = await fetchMonthlySummary(conn, monthDate);
    await fsPromises.mkdir(outputDirectory, { recursive: true });
    await renderMonthlyReportPdf(outputPath, summary);

    const reportId = existing?.id || uuidv4();
    await conn.query(
      `INSERT INTO monthly_reports (id, report_month, status, storage_path, generated_by, summary, generated_at)
       VALUES (?, ?, 'generated', ?, ?, ?, NOW(3))
       ON DUPLICATE KEY UPDATE
         status = VALUES(status),
         storage_path = VALUES(storage_path),
         generated_by = VALUES(generated_by),
         summary = VALUES(summary),
         generated_at = VALUES(generated_at)`,
      [reportId, reportMonthValue, outputPath, generatedBy, JSON.stringify(summary)]
    );

    const report = {
      id: reportId,
      report_month: reportMonthValue,
      status: 'generated',
      storage_path: outputPath,
      generated_by: generatedBy,
      generated_at: new Date().toISOString(),
      summary,
      reused: false,
    };

    notifyMonthlyReportGenerated({ report }).catch((notifyErr) => {
      console.error('Monthly report notification error:', notifyErr);
    });

    return report;
  } finally {
    conn.release();
  }
}

module.exports = {
  generateMonthlyReport,
  getMonthlyReportById,
  getMonthKey,
  getPreviousMonthDate,
  listMonthlyReports,
  parseMonthInput,
};