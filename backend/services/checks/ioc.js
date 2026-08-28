const axios = require('axios');

const TIMEOUT = 10000;

// Suspicious paths that may indicate a compromised site
const SUSPICIOUS_PATHS = [
  { path: '/wp-content/uploads/shell.php', label: 'вебшел' },
  { path: '/wp-content/uploads/cmd.php', label: 'вебшел' },
  { path: '/wp-includes/css/wp-admin.php', label: 'підроблений файл WP' },
  { path: '/wp-includes/js/wp-db.php', label: 'підроблений файл WP' },
  { path: '/wp-content/themes/twentytwentythree/evil.php', label: 'впроваджений файл' },
  { path: '/wp-content/cache/.htaccess.bak', label: 'витік резервної копії' },
  { path: '/.git/HEAD', label: 'відкритий git-репозиторій' },
  { path: '/.env', label: 'відкритий файл .env' },
  { path: '/wp-config.php.bak', label: 'резервна копія wp-config' },
  { path: '/wp-config.php~', label: 'резервна копія wp-config' },
  { path: '/error_log', label: 'відкритий error_log' },
  { path: '/debug.log', label: 'відкритий debug.log' },
  { path: '/wp-content/debug.log', label: 'відкритий debug.log WP' }
];

// Patterns in HTML that may indicate compromise or spam injection
const MALWARE_PATTERNS = [
  { regex: /eval\s*\(\s*base64_decode/i, label: 'патерн PHP eval/base64 у HTML' },
  { regex: /document\.write\s*\(\s*unescape/i, label: 'ін’єкція JS unescape' },
  { regex: /iframe[^>]+display:\s*none/i, label: 'ін’єкція прихованого iframe' },
  { regex: /<script[^>]*>[^<]*(?:document\.location|window\.location)\s*=/i, label: 'ін’єкція JS-редіректу' },
  { regex: /onmouseover\s*=\s*['"].*?window\.location/i, label: 'редірект через onmouseover' },
  { regex: /<\/?(marquee|blink)[^>]*>/i, label: 'ін’єкція спам-тегів HTML' },
  { regex: /pharmacy|cialis|viagra|casino|\bseo\b.*\bhref\b/i, label: 'ін’єкція спам-контенту' }
];

async function checkIOC(url) {
  const findings = [];

  // 1. Check for exposed sensitive files
  const fileChecks = await Promise.allSettled(
    SUSPICIOUS_PATHS.map(async ({ path, label }) => {
      try {
        const res = await axios.get(url + path, {
          timeout: 5000,
          validateStatus: () => true,
          maxRedirects: 2,
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WPSecurityScanner/1.0)' }
        });

        if (res.status === 200) {
          const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
          // Skip empty or redirect-to-home responses
          if (body.length > 50 && !body.includes('<title>WordPress</title>')) {
            return { path, label };
          }
        }
        return null;
      } catch (_) { return null; }
    })
  );

  for (const r of fileChecks) {
    if (r.status === 'fulfilled' && r.value) {
      const { path, label } = r.value;
      const isWebshell = label === 'вебшел' || label === 'підроблений файл WP';
      const isBackupOrLog = label.includes('резервн') || label.includes('log') || label.includes('лог');
      findings.push({
        type: 'ioc',
        severity: isWebshell ? 'critical' : isBackupOrLog ? 'medium' : 'high',
        title: `Відкрито: ${label} — ${path}`,
        detail: `Шлях ${path} повертає HTTP 200. Це може вказувати на скомпрометований або неправильно налаштований сайт.`,
        recommendation: isWebshell
          ? 'ТЕРМІНОВО: негайно перевірте цей файл — це може бути вебшел. Перегляньте логи сервера і відновіться з чистої резервної копії.'
          : `Обмежте доступ до ${path} через конфігурацію сервера або .htaccess.`
      });
    }
  }

  // 2. Scan homepage HTML for malware patterns
  try {
    const res = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WPSecurityScanner/1.0)' },
      maxRedirects: 5,
      validateStatus: s => s < 500
    });

    const html = typeof res.data === 'string' ? res.data : '';

    for (const { regex, label } of MALWARE_PATTERNS) {
      if (regex.test(html)) {
        findings.push({
          type: 'ioc',
          severity: 'high',
          title: `Виявлено підозрілий патерн: ${label}`,
          detail: `HTML головної сторінки містить патерн, пов’язаний зі шкідливим кодом або спам-ін’єкцією: «${label}».`,
          recommendation: 'Перевірте інсталяцію WordPress плагіном безпеки (напр. Wordfence) і перегляньте нещодавно змінені файли.'
        });
      }
    }

    // 3. Check for unexpected external scripts from known malware domains
    const externalScripts = [];
    const scriptMatches = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)];
    const knownMalwareDomains = [
      'trafficjunky', 'propellerads', 'clicksor', 'ero-advertising',
      'statcounter-evil', 'gstaticx', 'googletag-analytics'
    ];

    for (const m of scriptMatches) {
      const src = m[1];
      if (src.startsWith('http') && !src.includes(new URL(url).hostname)) {
        for (const badDomain of knownMalwareDomains) {
          if (src.includes(badDomain)) {
            externalScripts.push(src);
          }
        }
      }
    }

    if (externalScripts.length > 0) {
      findings.push({
        type: 'ioc',
        severity: 'critical',
        title: 'Підозріла ін’єкція зовнішнього скрипта',
        detail: `Знайдено скрипти з відомих шкідливих доменів: ${externalScripts.join(', ')}`,
        recommendation: 'Негайно видаліть ці скрипти й перевірте файли теми/плагінів.'
      });
    }

  } catch (err) {
    findings.push({
      type: 'error',
      severity: 'info',
      message: `Не вдалося просканувати HTML на IOC: ${err.message}`
    });
  }

  return findings;
}

module.exports = { checkIOC };
