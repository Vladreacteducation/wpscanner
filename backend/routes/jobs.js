const express = require('express');
const router = express.Router();

// GET /api/jobs/:id — poll job status & results
router.get('/:id', (req, res) => {
  const job = global.scanJobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Завдання не знайдено.' });
  res.json(job);
});

// GET /api/jobs/:id/export — download results as JSON
router.get('/:id/export', (req, res) => {
  const job = global.scanJobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Завдання не знайдено.' });

  res.setHeader('Content-Disposition', `attachment; filename="scan-${job.id}.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(job, null, 2));
});

module.exports = router;
