require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const scannerRouter = require('./routes/scanner');
const jobsRouter = require('./routes/jobs');

const app = express();
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';

// Behind a reverse proxy (nginx): trust X-Forwarded-* so req.ip is the real
// client and the rate limiter keys per visitor, not per proxy.
app.set('trust proxy', 1);

// In-memory job store (swap for Redis/DB in production)
global.scanJobs = new Map();

app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json());

// Trusted callers (the bulk runner) can bypass the limiter with a shared token
// so job polling during a batch scan is not throttled.
const BYPASS_TOKEN = process.env.SCAN_BYPASS_TOKEN || '';
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 50,
  skip: (req) => {
    if (BYPASS_TOKEN && req.get('X-Scan-Token') === BYPASS_TOKEN) return true;
    // Read-only status polling is frequent (UI polls every 2s) — don't count it.
    if (req.method === 'GET' && /^\/api\/(jobs\/|health)/.test(req.originalUrl)) return true;
    return false;
  },
  message: { error: 'Забагато запитів, спробуйте пізніше.' }
});
app.use('/api/', limiter);

app.use('/api/scan', scannerRouter);
app.use('/api/jobs', jobsRouter);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, HOST, () => {
  console.log(`WP Scanner backend running on ${HOST}:${PORT}`);
});
