const axios = require('axios');
const cheerio = require('cheerio');

const TIMEOUT = 12000;
const WPSCAN_API = 'https://wpscan.com/api/v3';

// --- Economy controls for the WPScan API (free tier: 25 req/day) ---
// Cache successful lookups so a plugin slug is queried at most once per TTL,
// deduped across every site in a run and across runs while the process lives.
const CACHE_TTL_MS = Number(process.env.WPSCAN_CACHE_TTL_MS) || 24 * 60 * 60 * 1000;
// Hard cap on API calls per rolling day. Once spent, remaining plugins are
// reported as "not checked" instead of silently failing.
const DAILY_BUDGET = Number(process.env.WPSCAN_DAILY_BUDGET) || 25;
// Fewer plugin queries per site — the noisiest source of API spend.
const MAX_PLUGINS_PER_SITE = Number(process.env.WPSCAN_MAX_PLUGINS) || 5;

const wpscanCache = new Map(); // slug -> { vulns, expires }
let budget = { day: currentDay(), used: 0 };

function currentDay() {
  return new Date().toISOString().slice(0, 10);
}

function budgetRemaining() {
  if (budget.day !== currentDay()) budget = { day: currentDay(), used: 0 };
  return DAILY_BUDGET - budget.used;
}

// Detect plugins from HTML source (wp-content/plugins/SLUG/)
async function detectPluginsFromHTML(url) {
  const plugins = new Map(); // slug -> version or null

  try {
    const res = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WPSecurityScanner/1.0)' },
      maxRedirects: 5,
      validateStatus: s => s < 500
    });

    const html = typeof res.data === 'string' ? res.data : '';
    const $ = cheerio.load(html);

    // Extract from script/link src paths
    $('script[src], link[href]').each((_, el) => {
      const src = $(el).attr('src') || $(el).attr('href') || '';
      const match = src.match(/\/wp-content\/plugins\/([^/]+)/);
      if (match) {
        const slug = match[1];
        const verMatch = src.match(/[?&]ver=([\d.]+)/);
        if (!plugins.has(slug)) {
          plugins.set(slug, verMatch ? verMatch[1] : null);
        }
      }
    });

    // Also check inline comments sometimes added by builders
    const pluginRefs = [...html.matchAll(/\/wp-content\/plugins\/([a-z0-9_-]+)/g)];
    for (const m of pluginRefs) {
      if (!plugins.has(m[1])) plugins.set(m[1], null);
    }

  } catch (_) {}

  return plugins;
}

// Query WPScan API for plugin vulnerabilities.
// Returns an array of vuln objects, or null when the lookup could not be done
// (no key, network error, or daily budget exhausted).
async function queryWPScan(slug, version) {
  const apiKey = process.env.WPSCAN_API_KEY;
  if (!apiKey) return null; // API key not configured

  // 1. Serve from cache when possible — costs no quota.
  const cached = wpscanCache.get(slug);
  if (cached && cached.expires > Date.now()) {
    return filterVulns(cached.vulns, version);
  }

  // 2. Respect the daily budget.
  if (budgetRemaining() <= 0) return null;

  try {
    budget.used++;
    const res = await axios.get(`${WPSCAN_API}/plugins/${slug}`, {
      timeout: 8000,
      headers: {
        'Authorization': `Token token=${apiKey}`,
        'User-Agent': 'WPSecurityScanner/1.0'
      },
      validateStatus: s => s < 500
    });

    if (res.status !== 200 || !res.data) return null;

    const data = res.data[slug];
    const allVulns = (data && data.vulnerabilities) || [];

    // Cache the raw list (even when empty) so the slug is not re-queried.
    wpscanCache.set(slug, { vulns: allVulns, expires: Date.now() + CACHE_TTL_MS });

    return filterVulns(allVulns, version);

  } catch (_) {
    return null;
  }
}

// Keep only vulns affecting the detected version, normalised for output.
function filterVulns(vulnerabilities, version) {
  return vulnerabilities.filter(vuln => {
    if (!version) return true; // unknown version — report all
    const fixed = vuln.fixed_in;
    if (!fixed) return true; // no fix known — still vulnerable
    return compareVersions(version, fixed) < 0;
  }).map(vuln => ({
    id: vuln.id,
    title: vuln.title,
    cvss: vuln.cvss?.score || null,
    cve: vuln.references?.cve?.[0] || null,
    fixed_in: vuln.fixed_in,
    url: vuln.references?.url?.[0] || null
  }));
}

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

async function checkPluginsWPScan(url) {
  const findings = [];
  const plugins = await detectPluginsFromHTML(url);

  if (plugins.size === 0) {
    findings.push({
      type: 'plugins',
      severity: 'info',
      title: 'Плагіни не виявлені у коді сторінки',
      detail: 'Не вдалося визначити плагіни з HTML. Можливо, це не WordPress-сайт або використовується серверний рендеринг.',
      recommendation: null
    });
    return findings;
  }

  findings.push({
    type: 'plugins',
    severity: 'info',
    title: `Виявлено плагінів: ${plugins.size}`,
    detail: [...plugins.entries()].map(([slug, ver]) => `${slug}${ver ? ` v${ver}` : ''}`).join(', '),
    recommendation: null
  });

  if (!process.env.WPSCAN_API_KEY) {
    findings.push({
      type: 'plugins',
      severity: 'info',
      title: 'Ключ WPScan API не налаштований',
      detail: 'Вкажіть WPSCAN_API_KEY у .env, щоб увімкнути пошук CVE для виявлених плагінів.',
      recommendation: 'Отримайте безкоштовний ключ на https://wpscan.com/api'
    });
    return findings;
  }

  // Query a bounded number of plugins per site to conserve the daily API quota.
  const pluginList = [...plugins.entries()].slice(0, MAX_PLUGINS_PER_SITE);
  const skippedForCap = plugins.size - pluginList.length;

  let skippedForBudget = 0;
  await Promise.allSettled(pluginList.map(async ([slug, version]) => {
    const vulns = await queryWPScan(slug, version);
    if (vulns === null) {
      // Only count as budget-skipped when a key is set but nothing came back
      // and the slug is not cached — i.e. quota is the likely cause.
      if (!wpscanCache.has(slug) && budgetRemaining() <= 0) skippedForBudget++;
      return;
    }
    if (vulns.length === 0) return;

    for (const v of vulns) {
      const severity = v.cvss >= 9 ? 'critical' : v.cvss >= 7 ? 'high' : v.cvss >= 4 ? 'medium' : 'low';
      findings.push({
        type: 'plugin_vuln',
        severity,
        title: v.title,
        detail: [
          `Плагін: ${slug}${version ? ` (v${version})` : ''}`,
          v.cve ? `CVE: CVE-${v.cve}` : '',
          v.cvss ? `CVSS: ${v.cvss}` : '',
          v.fixed_in ? `Виправлено у: ${v.fixed_in}` : 'Виправлення поки немає'
        ].filter(Boolean).join(' · '),
        recommendation: v.fixed_in
          ? `Оновіть ${slug} до версії ${v.fixed_in} або новішої.`
          : `Патча немає. Розгляньте вимкнення або заміну ${slug}.`,
        cve: v.cve,
        cvss: v.cvss,
        plugin: slug,
        version,
        fixed_in: v.fixed_in,
        ref: v.url
      });
    }
  }));

  if (skippedForBudget > 0) {
    findings.push({
      type: 'plugins',
      severity: 'info',
      title: 'Пошук CVE у WPScan пропущено — вичерпано денний ліміт API',
      detail: `Плагінів не перевірено через WPScan: ${skippedForBudget} (ліміт: ${DAILY_BUDGET}/добу). Кешовані результати використані там, де були доступні.`,
      recommendation: 'Збільште WPSCAN_DAILY_BUDGET (платний план) або повторіть скан завтра.'
    });
  }
  if (skippedForCap > 0) {
    findings.push({
      type: 'plugins',
      severity: 'info',
      title: `Через WPScan перевірено лише перші ${MAX_PLUGINS_PER_SITE} плагінів`,
      detail: `Ще плагінів не запитано: ${skippedForCap} (ліміт на сайт для економії квоти API).`,
      recommendation: 'Збільште WPSCAN_MAX_PLUGINS, щоб перевіряти більше плагінів на сайт.'
    });
  }

  return findings;
}

module.exports = { checkPluginsWPScan };
