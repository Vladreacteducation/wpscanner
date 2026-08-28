const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { runScanJob } = require('../services/scanOrchestrator');

// POST /api/scan — start a new scan job
router.post('/', async (req, res) => {
  const { sites, checks } = req.body;

  if (!sites || !Array.isArray(sites) || sites.length === 0) {
    return res.status(400).json({ error: 'Вкажіть хоча б одну URL-адресу сайту.' });
  }
  if (sites.length > 50) {
    return res.status(400).json({ error: 'Максимум 50 сайтів за один скан.' });
  }

  const validChecks = ['plugins', 'endpoints', 'version_leak', 'ioc'];
  const selectedChecks = (checks || validChecks).filter(c => validChecks.includes(c));

  const jobId = uuidv4();
  const job = {
    id: jobId,
    status: 'queued',
    createdAt: new Date().toISOString(),
    sites: sites.map(url => normalizeUrl(url)),
    checks: selectedChecks,
    results: [],
    progress: 0,
    total: sites.length
  };

  global.scanJobs.set(jobId, job);

  // Run async (non-blocking)
  runScanJob(jobId).catch(err => {
    const j = global.scanJobs.get(jobId);
    if (j) { j.status = 'error'; j.error = err.message; }
  });

  res.json({ jobId, status: 'queued', total: sites.length });
});

function normalizeUrl(url) {
  url = url.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  return url.replace(/\/$/, '');
}

module.exports = router;
