const express = require('express');
const path = require('path');

const { generateMonthlyReport, getMonthlyReportById, listMonthlyReports } = require('../services/reporting');

const router = express.Router();

router.get('/monthly', async (req, res) => {
  try {
    const limit = Number(req.query.limit || 12);
    const reports = await listMonthlyReports(limit);
    return res.json({ reports });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/monthly/generate', async (req, res) => {
  try {
    const { month, actor_id, force } = req.body || {};
    const report = await generateMonthlyReport({
      month,
      generatedBy: actor_id || null,
      force: Boolean(force),
    });

    return res.status(report.reused ? 200 : 201).json({ report });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: err.message || 'Unable to generate report' });
  }
});

router.get('/monthly/:id/download', async (req, res) => {
  try {
    const report = await getMonthlyReportById(req.params.id);
    if (!report || !report.storage_path) {
      return res.status(404).json({ error: 'Report not found' });
    }

    return res.download(report.storage_path, path.basename(report.storage_path));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;