# WPGuard — WordPress Vulnerability Scanner

Веб-система для перевірки WordPress-сайтів на вразливості. Тільки для своїх сайтів або з дозволу власника.

## Що перевіряє

| Перевірка | Що шукає |
|-----------|----------|
| **Plugin/Theme CVEs** | Застарілі плагіни через WPScan API + CVE бази |
| **Exposed Endpoints** | xmlrpc.php, wp-json users, ?author= enumeration, wp-login |
| **Version Disclosure** | wp-generator meta, ?ver= в assets, readme.html |
| **Compromise IOC** | Webshells, .env exposed, git exposed, malware patterns в HTML |

## Швидкий запуск (Docker)

```bash
# 1. Клонувати
git clone <your-repo>
cd wp-scanner

# 2. Налаштувати
cp backend/.env.example backend/.env
# Відредагувати backend/.env:
#   WPSCAN_API_KEY=ваш_ключ (отримати на wpscan.com/api)
#   FRONTEND_URL=https://scanner.yourdomain.com

# 3. Запустити
docker compose up -d --build
```

Відкрити: http://localhost:3000

## Запуск без Docker

```bash
# Backend
cd backend
npm install
cp .env.example .env
# заповнити .env
node server.js

# Frontend (другий термінал)
cd frontend
npm install
npm start
```

## Налаштування на піддомені (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name scanner.yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
    }

    location /api/ {
        proxy_pass http://localhost:3001;
    }
}
```

## Змінні оточення (backend/.env)

| Змінна | Опис |
|--------|------|
| `PORT` | Порт бекенду (default: 3001) |
| `FRONTEND_URL` | URL фронтенду для CORS |
| `WPSCAN_API_KEY` | API ключ WPScan (безкоштовний tier: 25 запитів/добу) |

## Архітектура

```
React (port 3000)
    │  POST /api/scan → {jobId}
    │  GET  /api/jobs/:id → poll results
    ▼
Express (port 3001)
    ├── scanOrchestrator.js  ← паралельний запуск перевірок
    ├── checks/
    │   ├── versionLeak.js   ← meta generator, ?ver=, readme.html
    │   ├── endpoints.js     ← xmlrpc, wp-json, wp-login, ?author=
    │   ├── wpscanPlugins.js ← detect plugins + WPScan API CVE lookup
    │   └── ioc.js           ← suspicious files, malware HTML patterns
    └── routes/
        ├── scanner.js       ← POST /api/scan
        └── jobs.js          ← GET /api/jobs/:id, GET /api/jobs/:id/export
```

## Ліміти

- Максимум 50 сайтів за один запуск
- Паралельне сканування: 3 сайти одночасно
- Rate limit: 50 запитів / 15 хвилин
- WPScan API (безкоштовний): 25 запитів/добу → для більшого обсягу — платний план

### Економія WPScan API

Щоб не вигоряти денний ліміт, бекенд:

- **кешує** відповіді WPScan по slug плагіна (`WPSCAN_CACHE_TTL_MS`, default 24 год) — один плагін запитується раз, дедуплікація по всіх сайтах прогону;
- тримає **денний бюджет** викликів (`WPSCAN_DAILY_BUDGET`, default 25) — після вичерпання решта плагінів позначається як «не перевірено», а не мовчки падає;
- обмежує **кількість плагінів на сайт** (`WPSCAN_MAX_PLUGINS`, default 5).

## Правовий аспект

Скануйте тільки сайти, які вам належать або власники яких дали письмовий дозвіл.
