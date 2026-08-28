import React from 'react';

const STATUS_LABELS = {
  queued:    { label: 'У черзі',      color: '#6b7280' },
  running:   { label: 'Сканування…',  color: '#3b82f6' },
  completed: { label: 'Завершено',    color: '#10b981' },
  error:     { label: 'Помилка',      color: '#ef4444' }
};

export default function JobStatus({ job }) {
  if (!job) return null;

  const { status, progress = 0, total = 1, results = [] } = job;
  const pct = Math.round((progress / total) * 100);
  const meta = STATUS_LABELS[status] || STATUS_LABELS.queued;

  const critical = results.filter(r => r.riskLevel === 'critical').length;
  const high     = results.filter(r => r.riskLevel === 'high').length;
  const medium   = results.filter(r => r.riskLevel === 'medium').length;
  const safe     = results.filter(r => r.riskLevel === 'safe').length;

  return (
    <div className="job-status">
      <div className="status-header">
        <div className="status-badge" style={{ background: meta.color }}>
          {status === 'running' && <span className="pulse-dot" />}
          {meta.label}
        </div>
        <span className="status-progress-text">
          {progress} / {total} сайтів проскановано
        </span>
      </div>

      <div className="progress-bar-track">
        <div
          className="progress-bar-fill"
          style={{ width: `${pct}%`, background: meta.color }}
        />
      </div>

      {results.length > 0 && (
        <div className="status-stats">
          {critical > 0 && <span className="stat critical">🔴 {critical} критичних</span>}
          {high     > 0 && <span className="stat high">🟠 {high} високих</span>}
          {medium   > 0 && <span className="stat medium">🟡 {medium} середніх</span>}
          {safe     > 0 && <span className="stat safe">🟢 {safe} безпечних</span>}
        </div>
      )}

      {job.error && (
        <div className="form-error">Помилка завдання: {job.error}</div>
      )}
    </div>
  );
}
