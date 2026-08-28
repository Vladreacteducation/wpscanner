import React, { useState } from 'react';

const RISK_META = {
  critical: { color: '#ef4444', bg: '#fef2f2', icon: '🔴', label: 'Критичний' },
  high:     { color: '#f97316', bg: '#fff7ed', icon: '🟠', label: 'Високий' },
  medium:   { color: '#eab308', bg: '#fefce8', icon: '🟡', label: 'Середній' },
  low:      { color: '#6b7280', bg: '#f9fafb', icon: '⚪', label: 'Низький' },
  safe:     { color: '#10b981', bg: '#f0fdf4', icon: '🟢', label: 'Безпечно' },
  unknown:  { color: '#6b7280', bg: '#f9fafb', icon: '❓', label: 'Невідомо' }
};

const RISK_FILTER_LABELS = {
  all: 'Усі',
  critical: 'Критичні',
  high: 'Високі',
  medium: 'Середні',
  low: 'Низькі',
  safe: 'Безпечні'
};

const SEV_LABELS = {
  critical: 'критичний',
  high: 'високий',
  medium: 'середній',
  low: 'низький',
  info: 'інфо'
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function ResultsPanel({ results, onExport }) {
  const [filter, setFilter] = useState('all');
  const [expanded, setExpanded] = useState(new Set());
  const [search, setSearch] = useState('');

  const toggle = (url) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(url) ? next.delete(url) : next.add(url);
      return next;
    });
  };

  const filtered = results
    .filter(r => filter === 'all' || r.riskLevel === filter)
    .filter(r => !search || r.url.toLowerCase().includes(search.toLowerCase()));

  const sorted = [...filtered].sort((a, b) =>
    (SEV_ORDER[a.riskLevel] ?? 9) - (SEV_ORDER[b.riskLevel] ?? 9)
  );

  const counts = results.reduce((acc, r) => {
    acc[r.riskLevel] = (acc[r.riskLevel] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="results-panel">
      <div className="results-header">
        <h3>Результати скану <span className="results-count">{results.length} сайтів</span></h3>
        <button className="btn btn-ghost" onClick={onExport}>↓ Експорт JSON</button>
      </div>

      <div className="results-controls">
        <div className="filter-tabs">
          {['all', 'critical', 'high', 'medium', 'low', 'safe'].map(f => (
            <button
              key={f}
              className={`filter-tab ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f === 'all'
                ? `${RISK_FILTER_LABELS.all} (${results.length})`
                : `${RISK_META[f]?.icon} ${RISK_FILTER_LABELS[f]} (${counts[f] || 0})`}
            </button>
          ))}
        </div>
        <input
          className="search-input"
          placeholder="Фільтр за URL…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      <div className="results-list">
        {sorted.length === 0 && (
          <div className="empty-state">Немає результатів за поточним фільтром.</div>
        )}
        {sorted.map(site => (
          <SiteResult
            key={site.url}
            site={site}
            expanded={expanded.has(site.url)}
            onToggle={() => toggle(site.url)}
          />
        ))}
      </div>
    </div>
  );
}

function SiteResult({ site, expanded, onToggle }) {
  const meta = RISK_META[site.riskLevel] || RISK_META.unknown;
  const findings = (site.findings || []).filter(f => f.severity !== 'info');
  const infoFindings = (site.findings || []).filter(f => f.severity === 'info');

  return (
    <div className="site-card" style={{ borderLeftColor: meta.color }}>
      <button className="site-card-header" onClick={onToggle}>
        <div className="site-info">
          <span className="site-risk-badge" style={{ background: meta.bg, color: meta.color }}>
            {meta.icon} {meta.label}
          </span>
          <span className="site-url">{site.url}</span>
          {site.status === 'unreachable' && (
            <span className="badge-unreachable">Недоступний</span>
          )}
        </div>
        <div className="site-summary">
          {findings.length > 0 && (
            <span className="finding-count">{findings.length} {pluralFindings(findings.length)}</span>
          )}
          <span className="expand-icon">{expanded ? '▲' : '▼'}</span>
        </div>
      </button>

      {expanded && (
        <div className="site-findings">
          {findings.length === 0 && infoFindings.length === 0 && (
            <div className="no-findings">Проблем не виявлено.</div>
          )}

          {findings.map((f, i) => (
            <FindingRow key={i} finding={f} />
          ))}

          {infoFindings.length > 0 && (
            <details className="info-details">
              <summary>ℹ {infoFindings.length} інформаційних</summary>
              {infoFindings.map((f, i) => (
                <div key={i} className="info-row">{f.title || f.message}</div>
              ))}
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function pluralFindings(n) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return 'знахідка';
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return 'знахідки';
  return 'знахідок';
}

function FindingRow({ finding }) {
  const SEV_COLORS = {
    critical: '#ef4444',
    high:     '#f97316',
    medium:   '#eab308',
    low:      '#6b7280',
    info:     '#3b82f6'
  };
  const color = SEV_COLORS[finding.severity] || '#6b7280';

  return (
    <div className="finding-row">
      <div className="finding-header">
        <span className="finding-sev" style={{ background: color }}>{SEV_LABELS[finding.severity] || finding.severity}</span>
        <span className="finding-title">{finding.title}</span>
        {finding.cve && (
          <a
            className="finding-cve"
            href={`https://nvd.nist.gov/vuln/detail/CVE-${finding.cve}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            CVE-{finding.cve}
          </a>
        )}
        {finding.cvss && (
          <span className="finding-cvss" title="Оцінка CVSS">CVSS {finding.cvss}</span>
        )}
      </div>
      {finding.detail && <p className="finding-detail">{finding.detail}</p>}
      {finding.recommendation && (
        <div className="finding-rec">
          <strong>Виправлення:</strong> {finding.recommendation}
          {finding.ref && (
            <a href={finding.ref} target="_blank" rel="noopener noreferrer"> ↗ Детальніше</a>
          )}
        </div>
      )}
    </div>
  );
}
