const axios = require('axios');
const cheerio = require('cheerio');

const TIMEOUT = 10000;

async function checkVersionLeak(url) {
  const findings = [];

  try {
    const res = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WPSecurityScanner/1.0)' },
      maxRedirects: 5,
      validateStatus: s => s < 500
    });

    const html = res.data;
    const $ = cheerio.load(html);

    // 1. <meta name="generator" content="WordPress X.X.X">
    const generator = $('meta[name="generator"]').attr('content') || '';
    const wpMatch = generator.match(/WordPress\s+([\d.]+)/i);
    if (wpMatch) {
      findings.push({
        type: 'version_leak',
        severity: 'medium',
        title: 'Версія WordPress розкрита в meta generator',
        detail: `Виявлено версію: ${wpMatch[1]}`,
        recommendation: 'Приберіть meta-тег generator. Додайте у functions.php: remove_action(\'wp_head\', \'wp_generator\');',
        version: wpMatch[1]
      });
    }

    // 2. Version in ?ver= query params on scripts/styles
    const verParams = new Set();
    $('script[src], link[rel="stylesheet"][href]').each((_, el) => {
      const src = $(el).attr('src') || $(el).attr('href') || '';
      const match = src.match(/[?&]ver=([\d.]+)/);
      if (match) verParams.add(match[1]);
    });

    if (verParams.size > 0) {
      findings.push({
        type: 'version_leak',
        severity: 'low',
        title: 'Рядки версій розкриті в URL ресурсів',
        detail: `Знайдено параметри ?ver=: ${[...verParams].slice(0, 5).join(', ')}`,
        recommendation: 'Приберіть параметри версії з підключених ресурсів, щоб унеможливити фінгерпринтинг.'
      });
    }

    // 3. readme.html / license.txt present (version inside)
    for (const path of ['/readme.html', '/license.txt', '/wp-links-opml.php']) {
      try {
        const r = await axios.get(url + path, { timeout: 5000, validateStatus: s => s < 500 });
        if (r.status === 200 && r.data.length > 100) {
          const vMatch = r.data.match(/WordPress\s+([\d.]+)/i) ||
                         r.data.match(/Version\s+([\d.]+)/i);
          findings.push({
            type: 'version_leak',
            severity: 'low',
            title: `Доступний файл: ${path}`,
            detail: vMatch ? `Містить згадку версії: ${vMatch[1]}` : 'Файл доступний публічно',
            recommendation: `Заблокуйте доступ до ${path} у .htaccess або конфігурації nginx.`
          });
        }
      } catch (_) {}
    }

  } catch (err) {
    findings.push({
      type: 'error',
      severity: 'info',
      message: `Не вдалося виконати перевірку витоку версії: ${err.message}`
    });
  }

  return findings;
}

module.exports = { checkVersionLeak };
