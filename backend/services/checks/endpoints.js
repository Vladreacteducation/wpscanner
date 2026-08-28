const axios = require('axios');

const TIMEOUT = 8000;

const ENDPOINTS = [
  {
    path: '/xmlrpc.php',
    method: 'POST',
    body: '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
    headers: { 'Content-Type': 'text/xml' },
    detect: (status, data) => status === 200 && data.includes('system.listMethods'),
    severity: 'high',
    title: 'XML-RPC увімкнено',
    detail: 'xmlrpc.php доступний публічно і відповідає на виклики методів.',
    recommendation: 'Вимкніть XML-RPC, якщо він не потрібен. Додайте в .htaccess: <Files xmlrpc.php> Order Deny,Allow Deny from all </Files>'
  },
  {
    path: '/wp-json/wp/v2/users',
    method: 'GET',
    detect: (status, data) => status === 200 && data.includes('"id"'),
    severity: 'medium',
    title: 'Перелічення користувачів через REST API',
    detail: 'WP REST API віддає список облікових записів користувачів.',
    recommendation: 'Обмежте доступ до /wp-json/wp/v2/users лише автентифікованими запитами.'
  },
  {
    path: '/wp-json/',
    method: 'GET',
    detect: (status, data) => status === 200 && data.includes('"namespaces"'),
    severity: 'low',
    title: 'WP REST API відкритий',
    detail: 'Корінь REST API доступний публічно і розкриває метадані сайту.',
    recommendation: 'Розгляньте обмеження неавтентифікованого доступу до REST API.'
  },
  {
    path: '/wp-login.php',
    method: 'GET',
    detect: (status, data) => status === 200 && (data.includes('wp-login') || data.includes('user_login')),
    severity: 'low',
    title: 'Сторінка входу доступна публічно',
    detail: 'wp-login.php доступний без обмежень за IP.',
    recommendation: 'Обмежте wp-login.php за IP у конфігурації сервера або використайте плагін захисту входу.'
  },
  {
    path: '/?author=1',
    method: 'GET',
    detect: (status, data, headers, finalUrl) =>
      finalUrl && finalUrl.includes('/author/'),
    severity: 'medium',
    title: 'Перелічення авторів через параметр ?author=',
    detail: 'Запит перенаправляє на /author/[username]/, розкриваючи імена користувачів.',
    recommendation: 'Заблокуйте перелічення через ?author= правилом перезапису або плагіном безпеки.'
  },
  {
    path: '/wp-cron.php',
    method: 'GET',
    detect: (status) => status === 200,
    severity: 'low',
    title: 'wp-cron.php доступний публічно',
    detail: 'Точку cron можна викликати ззовні, створюючи навантаження.',
    recommendation: 'Вимкніть стандартний WP-Cron і використайте реальний серверний cron.'
  }
];

async function checkEndpoints(url) {
  const findings = [];

  await Promise.allSettled(
    ENDPOINTS.map(async (ep) => {
      try {
        const config = {
          method: ep.method,
          url: url + ep.path,
          timeout: TIMEOUT,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; WPSecurityScanner/1.0)',
            ...(ep.headers || {})
          },
          data: ep.body,
          maxRedirects: 5,
          validateStatus: () => true
        };

        let finalUrl = url + ep.path;
        config.onRedirect = (response) => { finalUrl = response.headers.location || finalUrl; };

        const res = await axios(config);
        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

        if (ep.detect(res.status, body, res.headers, finalUrl)) {
          findings.push({
            type: 'endpoint',
            severity: ep.severity,
            title: ep.title,
            detail: ep.detail,
            recommendation: ep.recommendation,
            endpoint: ep.path
          });
        }
      } catch (_) {}
    })
  );

  return findings;
}

module.exports = { checkEndpoints };
