import { useEffect, useState } from 'react';
import { getEvents, runCorrelation, clearLog, type SecurityEvent, type Investigation } from '../../lib/soc';

function severityBadge(sev: string) {
  const cls = sev === 'critical' ? 'badge-critical' : sev === 'warning' ? 'badge-warn' : 'badge-info';
  return <span className={`badge ${cls}`}>{sev}</span>;
}

export default function SOCDashboard() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);

  async function refresh() {
    setEvents(await getEvents(100));
    setInvestigations(await runCorrelation());
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div className="stack">
      <div className="row-between">
        <div>
          <h1>SOC Monitor</h1>
          <p className="section-desc">Every sensitive action on this device, correlated into investigations you can triage.</p>
        </div>
        <button className="btn" onClick={refresh}>Refresh</button>
      </div>

      <div>
        <h2 style={{ marginBottom: 10 }}>Investigations ({investigations.length})</h2>
        {investigations.length === 0 ? (
          <div className="empty-state">No active investigations. Everything looks normal.</div>
        ) : (
          investigations.map((inv, i) => (
            <div className="card" key={i} style={{ marginBottom: 10 }}>
              <div className="row-between">
                <h2 style={{ margin: 0 }}>{inv.title}</h2>
                {severityBadge(inv.severity)}
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-dim)', marginTop: 8 }}>{inv.summary}</p>
              <p style={{ fontSize: 11.5, color: 'var(--text-dim)', marginTop: 6 }}>
                {inv.events.length} event(s) · latest {new Date(inv.latestTimestamp).toLocaleString()}
              </p>
            </div>
          ))
        )}
      </div>

      <div>
        <div className="row-between" style={{ marginBottom: 10 }}>
          <h2 style={{ margin: 0 }}>Raw event log</h2>
          <button
            className="btn btn-danger"
            onClick={async () => {
              if (confirm('Clear the entire local security log? This cannot be undone.')) {
                await clearLog();
                await refresh();
              }
            }}
          >
            Clear log
          </button>
        </div>
        <div className="card scrollbar-thin" style={{ maxHeight: 360, overflowY: 'auto', padding: 0 }}>
          {events.length === 0 ? (
            <div className="empty-state">No events yet.</div>
          ) : (
            events.map((e) => (
              <div key={e.id} className="row-between" style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)' }}>
                <div className="row">
                  {severityBadge(e.severity)}
                  <span style={{ fontSize: 13 }}>{e.type}{e.detail ? ` — ${e.detail}` : ''}</span>
                </div>
                <span style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>{new Date(e.timestamp).toLocaleTimeString()}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
