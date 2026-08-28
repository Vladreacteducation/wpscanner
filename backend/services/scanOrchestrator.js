const { checkVersionLeak } = require('./checks/versionLeak');
const { checkEndpoints } = require('./checks/endpoints');
const { checkPluginsWPScan } = require('./checks/wpscanPlugins');
const { checkIOC } = require('./checks/ioc');

const CONCURRENCY = 3; // scan N sites in parallel

async function runScanJob(jobId) {
  const job = global.scanJobs.get(jobId);
  if (!job) return;

  job.status = 'running';
  job.startedAt = new Date().toISOString();

  const queue = [...job.sites];
  let index = 0;

  async function processNext() {
    if (queue.length === 0) return;
    const url = queue.shift();
    const siteResult = await scanSite(url, job.checks);

    job.results.push(siteResult);
    job.progress = job.results.length;

    const j = global.scanJobs.get(jobId);
    if (j) Object.assign(j, job);
  }

  // Run in batches
  while (index < job.sites.length) {
    const batch = [];
    for (let i = 0; i < CONCURRENCY && queue.length > 0; i++) {
      batch.push(processNext());
    }
    await Promise.allSettled(batch);
    index += CONCURRENCY;
  }

  job.status = 'completed';
  job.completedAt = new Date().toISOString();

  const j = global.scanJobs.get(jobId);
  if (j) Object.assign(j, job);
}

async function scanSite(url, checks) {
  const result = {
    url,
    scannedAt: new Date().toISOString(),
    status: 'ok',
    riskLevel: 'unknown',
    findings: []
  };

  const runners = [];

  if (checks.includes('version_leak')) runners.push(checkVersionLeak(url));
  if (checks.includes('endpoints'))    runners.push(checkEndpoints(url));
  if (checks.includes('plugins'))      runners.push(checkPluginsWPScan(url));
  if (checks.includes('ioc'))          runners.push(checkIOC(url));

  const settled = await Promise.allSettled(runners);
  for (const r of settled) {
    if (r.status === 'fulfilled' && r.value) {
      result.findings.push(...r.value);
    } else if (r.status === 'rejected') {
      result.findings.push({
        type: 'error',
        severity: 'info',
        message: `Перевірка не виконана: ${r.reason?.message || 'невідома помилка'}`
      });
    }
  }

  // Determine overall risk
  const severities = result.findings.map(f => f.severity);
  if (severities.includes('critical'))      result.riskLevel = 'critical';
  else if (severities.includes('high'))     result.riskLevel = 'high';
  else if (severities.includes('medium'))   result.riskLevel = 'medium';
  else if (severities.includes('low'))      result.riskLevel = 'low';
  else                                       result.riskLevel = 'safe';

  if (result.findings.some(f => f.type === 'error' && f.message.includes('ECONNREFUSED'))) {
    result.status = 'unreachable';
  }

  return result;
}

module.exports = { runScanJob };
