import React, { useState, useRef, useCallback } from 'react';
import './App.css';
import ScanForm from './components/ScanForm';
import JobStatus from './components/JobStatus';
import ResultsPanel from './components/ResultsPanel';

const API_BASE = process.env.REACT_APP_API_URL || '';

function App() {
  const [activeJob, setActiveJob] = useState(null);
  const [jobData, setJobData] = useState(null);
  const pollRef = useRef(null);

  const startScan = useCallback(async ({ sites, checks }) => {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sites, checks })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Не вдалося запустити скан');

    setActiveJob(data.jobId);
    setJobData({ ...data, status: 'queued', results: [] });
    startPolling(data.jobId);
  }, []);

  const startPolling = useCallback((jobId) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/jobs/${jobId}`);
        const data = await res.json();
        setJobData(data);
        if (data.status === 'completed' || data.status === 'error') {
          clearInterval(pollRef.current);
        }
      } catch (_) {}
    }, 2000);
  }, []);

  const handleReset = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    setActiveJob(null);
    setJobData(null);
  };

  const handleExport = () => {
    if (!activeJob) return;
    window.open(`${API_BASE}/api/jobs/${activeJob}/export`, '_blank');
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-inner">
          <div className="logo">
            <span className="logo-icon">⚡</span>
            <div>
              <h1>WP<span className="accent">Guard</span></h1>
              <p className="tagline">Сканер вразливостей WordPress</p>
            </div>
          </div>
          {jobData?.status === 'completed' && (
            <button className="btn btn-ghost" onClick={handleReset}>← Новий скан</button>
          )}
        </div>
      </header>

      <main className="app-main">
        {!activeJob ? (
          <ScanForm onSubmit={startScan} />
        ) : (
          <div className="scan-view">
            <JobStatus job={jobData} />
            {jobData?.results?.length > 0 && (
              <ResultsPanel results={jobData.results} onExport={handleExport} />
            )}
          </div>
        )}
      </main>

      <footer className="app-footer">
        <p>Скануйте лише сайти, якими ви володієте або маєте письмовий дозвіл на тестування.</p>
      </footer>
    </div>
  );
}

export default App;
