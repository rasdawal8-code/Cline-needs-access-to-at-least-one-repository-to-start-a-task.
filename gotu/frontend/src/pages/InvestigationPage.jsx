import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useInvestigationStore } from '../stores/investigations.js';
import { Play, Square, Pause, RotateCcw, Trash2, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react';
import { api } from '../api/client.js';

const BADGE = {
  confirmed:  'status-confirmed', probable: 'status-probable',
  possible:   'status-possible',  unverified: 'status-unverified',
};

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-gotu-border rounded-md overflow-hidden">
      <button className="w-full flex items-center gap-3 p-3 text-left hover:bg-gotu-border hover:bg-opacity-30"
        onClick={() => setOpen(o => !o)}>
        <span className={`gotu-badge ${BADGE[finding.confidence] ?? 'gotu-badge-gray'}`}>{finding.confidence}</span>
        <span className="text-xs font-mono text-gotu-muted flex-1">{finding.type}</span>
        <span className="text-xs text-gotu-muted">{finding.source_name ?? '—'}</span>
        {open ? <ChevronUp size={12} className="text-gotu-muted" /> : <ChevronDown size={12} className="text-gotu-muted" />}
      </button>
      {open && (
        <div className="p-3 pt-0 border-t border-gotu-border">
          <pre className="text-xs text-gotu-muted overflow-auto max-h-48 bg-gotu-bg rounded p-2">
            {JSON.stringify(finding.data, null, 2)}
          </pre>
          {finding.source_url && (
            <a href={finding.source_url} target="_blank" rel="noopener noreferrer"
              className="text-xs text-gotu-accent hover:underline mt-2 block">Source ↗</a>
          )}
        </div>
      )}
    </div>
  );
}

function TabButton({ label, count, active, onClick }) {
  return (
    <button onClick={onClick}
      className={`px-3 py-2 text-sm font-medium border-b-2 transition-colors ${
        active ? 'border-gotu-accent text-gotu-accent' : 'border-transparent text-gotu-muted hover:text-gotu-text'}`}>
      {label}{count != null && <span className="ml-1.5 text-xs opacity-60">({count})</span>}
    </button>
  );
}

export default function InvestigationPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { current, findings, leads, graph, timeline, loading, loadInvestigation, startInvestigation, stopInvestigation, deleteInvestigation } = useInvestigationStore();
  const [tab, setTab] = useState('findings');
  const [acting, setActing] = useState(false);

  useEffect(() => { loadInvestigation(id); }, [id]);

  const act = async (fn) => { setActing(true); await fn(); setActing(false); await loadInvestigation(id); };
  const handleDelete = async () => {
    if (!confirm('Delete this investigation and all findings?')) return;
    const r = await deleteInvestigation(id);
    if (r.success) navigate('/dashboard');
  };

  if (loading || !current) return <div className="flex items-center justify-center h-64 text-gotu-muted">{loading ? 'Loading...' : 'Investigation not found.'}</div>;

  const statusColor = { running: 'text-gotu-accent', completed: 'text-gotu-success', failed: 'text-gotu-danger', stopped: 'text-gotu-muted', paused: 'text-gotu-warning', pending: 'text-gotu-muted' }[current.status] ?? 'text-gotu-muted';

  return (
    <div className="p-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-start gap-4 mb-6">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-xs font-mono font-bold uppercase ${statusColor}`}>{current.status}</span>
            <span className="text-gotu-muted">·</span>
            <span className="text-xs text-gotu-muted font-mono">{current.indicator_type}</span>
          </div>
          <h1 className="text-xl font-bold text-gotu-text">{current.title}</h1>
          <p className="text-sm text-gotu-muted font-mono mt-0.5">{current.indicator}</p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {current.status === 'pending' && (
            <button className="gotu-btn-primary flex items-center gap-1.5" disabled={acting}
              onClick={() => act(() => startInvestigation(id))}>
              <Play size={12} /> Start
            </button>
          )}
          {current.status === 'running' && (
            <>
              <button className="gotu-btn-secondary flex items-center gap-1.5" disabled={acting}
                onClick={() => act(() => api.investigations.pause(id))}>
                <Pause size={12} /> Pause
              </button>
              <button className="gotu-btn-danger flex items-center gap-1.5" disabled={acting}
                onClick={() => act(() => stopInvestigation(id))}>
                <Square size={12} /> Stop
              </button>
            </>
          )}
          {current.status === 'paused' && (
            <button className="gotu-btn-primary flex items-center gap-1.5" disabled={acting}
              onClick={() => act(() => api.investigations.resume(id))}>
              <RotateCcw size={12} /> Resume
            </button>
          )}
          {['stopped','completed','failed'].includes(current.status) && (
            <button className="gotu-btn-secondary flex items-center gap-1.5 text-gotu-danger border-gotu-danger border-opacity-30"
              onClick={handleDelete}>
              <Trash2 size={12} /> Delete
            </button>
          )}
          <button className="gotu-btn-secondary text-xs" onClick={() => loadInvestigation(id)}>↻ Refresh</button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        {[{ label: 'Findings', value: findings.length },
          { label: 'Leads', value: leads.length },
          { label: 'API Calls', value: current.api_calls_used ?? 0 },
          { label: 'Depth', value: current.current_depth ?? 0 }]
          .map(s => (
            <div key={s.label} className="gotu-card text-center py-3">
              <div className="text-lg font-bold text-gotu-text">{s.value}</div>
              <div className="text-xs text-gotu-muted">{s.label}</div>
            </div>
          ))}
      </div>

      {/* Tabs */}
      <div className="border-b border-gotu-border flex gap-1 mb-4">
        <TabButton label="Findings" count={findings.length}       active={tab==='findings'}  onClick={() => setTab('findings')} />
        <TabButton label="Leads"    count={leads.length}          active={tab==='leads'}     onClick={() => setTab('leads')} />
        <TabButton label="Timeline" count={timeline.length}       active={tab==='timeline'} onClick={() => setTab('timeline')} />
        <TabButton label="Graph"    count={graph.nodes.length}    active={tab==='graph'}    onClick={() => setTab('graph')} />
      </div>

      {/* Tab content */}
      {tab === 'findings' && (
        findings.length === 0
          ? <div className="text-center py-8 text-gotu-muted text-sm">No findings yet. Start the investigation.</div>
          : <div className="space-y-2">{findings.map(f => <FindingCard key={f.id} finding={f} />)}</div>
      )}

      {tab === 'leads' && (
        leads.length === 0
          ? <div className="text-center py-8 text-gotu-muted text-sm">No leads discovered yet.</div>
          : <div className="space-y-2">
              {leads.map(lead => (
                <div key={lead.id} className="gotu-card flex items-center gap-3">
                  <span className={`gotu-badge ${BADGE[lead.confidence] ?? 'gotu-badge-gray'}`}>{lead.confidence}</span>
                  <span className="text-xs font-mono text-gotu-muted">{lead.type}</span>
                  <span className="text-sm text-gotu-text flex-1 font-mono">{lead.value}</span>
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    lead.status === 'completed' ? 'text-gotu-success' :
                    lead.status === 'running'   ? 'text-gotu-accent' :
                    lead.status === 'pending'   ? 'text-gotu-muted' : 'text-gotu-warning'
                  }`}>{lead.status}</span>
                  {lead.status === 'pending' && current.require_lead_approval && (
                    <button className="text-xs text-gotu-accent hover:underline"
                      onClick={async () => { await api.investigations.approveLead(id, lead.id); loadInvestigation(id); }}>Approve</button>
                  )}
                </div>
              ))}
            </div>
      )}

      {tab === 'timeline' && (
        timeline.length === 0
          ? <div className="text-center py-8 text-gotu-muted text-sm">No timeline events yet.</div>
          : <div className="space-y-2">
              {timeline.map((ev, i) => (
                <div key={i} className="flex items-center gap-3 p-2 border border-gotu-border rounded-md">
                  <span className="text-xs text-gotu-muted font-mono w-32 flex-shrink-0">{ev.timestamp?.slice(0,19).replace('T','  ')}</span>
                  <span className="text-xs font-mono text-gotu-accent">{ev.event_type}</span>
                  <span className="text-xs text-gotu-text">{ev.value ?? ev.engine_id ?? '—'}</span>
                </div>
              ))}
            </div>
      )}

      {tab === 'graph' && (
        graph.nodes.length === 0
          ? <div className="text-center py-8 text-gotu-muted text-sm">No relationship graph data yet.</div>
          : <div className="gotu-card">
              <div className="text-xs text-gotu-muted mb-3">{graph.nodes.length} entities · {graph.edges.length} relationships</div>
              <div className="space-y-1">
                {graph.nodes.map(n => (
                  <div key={n.id} className="flex items-center gap-2 text-xs">
                    <span className="text-gotu-accent font-mono w-20 flex-shrink-0">{n.type}</span>
                    <span className="text-gotu-text">{n.label}</span>
                    <span className={`gotu-badge ${BADGE[n.confidence] ?? 'gotu-badge-gray'} ml-auto`}>{n.confidence}</span>
                  </div>
                ))}
              </div>
            </div>
      )}
    </div>
  );
}
