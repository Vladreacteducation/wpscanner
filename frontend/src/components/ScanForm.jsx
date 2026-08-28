import React, { useState } from 'react';

const CHECK_OPTIONS = [
  { id: 'plugins',      label: 'CVE плагінів/тем',        icon: '🔌', desc: 'Виявлення застарілих плагінів з відомими вразливостями через WPScan API' },
  { id: 'endpoints',    label: 'Відкриті точки доступу',  icon: '🔓', desc: 'Перевірка xmlrpc.php, відкритого REST API, доступності входу, перелічення користувачів' },
  { id: 'version_leak', label: 'Розкриття версії',        icon: '🏷️', desc: 'Виявлення витоку версії WordPress у meta-тегах та URL ресурсів' },
  { id: 'ioc',          label: 'Ознаки компрометації',    icon: '🚨', desc: 'Пошук вебшелів, відкритих конфіг-файлів, патернів шкідливого коду в HTML' },
];

export default function ScanForm({ onSubmit }) {
  const [sitesText, setSitesText] = useState('');
  const [checks, setChecks] = useState(['plugins', 'endpoints', 'version_leak', 'ioc']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const toggleCheck = (id) => {
    setChecks(prev =>
      prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id]
    );
  };

  const handleSubmit = async () => {
    setError('');
    const sites = sitesText
      .split('\n')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('#'));

    if (sites.length === 0) { setError('Введіть хоча б одну URL-адресу.'); return; }
    if (sites.length > 50)  { setError('Максимум 50 сайтів за один скан.'); return; }
    if (checks.length === 0) { setError('Оберіть хоча б одну перевірку.'); return; }

    setLoading(true);
    try {
      await onSubmit({ sites, checks });
    } catch (e) {
      setError(e.message);
      setLoading(false);
    }
  };

  const exampleSites = `https://example.com\nhttps://mysite.org\nhttps://client-site.net`;

  return (
    <div className="scan-form">
      <div className="form-hero">
        <h2>Сканування WordPress-сайтів</h2>
        <p>Введіть до 50 URL-адрес WordPress для перевірки на відомі вразливості, відкриті точки доступу та ознаки компрометації.</p>
      </div>

      <div className="form-grid">
        <div className="form-section">
          <label className="form-label">
            <span>URL-адреси сайтів</span>
            <span className="label-hint">по одній на рядок, максимум 50</span>
          </label>
          <textarea
            className="sites-input"
            value={sitesText}
            onChange={e => setSitesText(e.target.value)}
            placeholder={exampleSites}
            rows={10}
            spellCheck={false}
          />
          <div className="site-count">
            {sitesText.split('\n').filter(s => s.trim() && !s.trim().startsWith('#')).length} сайтів введено
          </div>
        </div>

        <div className="form-section">
          <label className="form-label">Перевірки для запуску</label>
          <div className="checks-grid">
            {CHECK_OPTIONS.map(opt => (
              <button
                key={opt.id}
                className={`check-card ${checks.includes(opt.id) ? 'active' : ''}`}
                onClick={() => toggleCheck(opt.id)}
                type="button"
              >
                <div className="check-header">
                  <span className="check-icon">{opt.icon}</span>
                  <span className="check-label">{opt.label}</span>
                  <span className="check-toggle">{checks.includes(opt.id) ? '✓' : '+'}</span>
                </div>
                <p className="check-desc">{opt.desc}</p>
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && <div className="form-error">⚠ {error}</div>}

      <button
        className="btn btn-primary btn-large"
        onClick={handleSubmit}
        disabled={loading}
      >
        {loading ? (
          <><span className="spinner" /> Запуск скану…</>
        ) : (
          <>⚡ Запустити скан безпеки</>
        )}
      </button>
    </div>
  );
}
