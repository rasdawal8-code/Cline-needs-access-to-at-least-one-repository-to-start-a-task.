import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useInvestigationStore } from '../stores/investigations.js';
import { Plus, Eye, Square, Play, Clock, CheckCircle, AlertCircle, PauseCircle } from 'lucide-react';

const STATUS_CONFIG = {
  pending:   { icon: Clock,        color: 'text-gotu-muted',    badge: 'gotu-badge-gray'  },
  running:   { icon: Play,         color: 'text-gotu-accent',   badge: 'gotu-badge-cyan'  },
  paused:    { icon: PauseCircle,  color: 'text-gotu-warning',  badge: 'gotu-badge-yellow'},
  stopped:   { icon: Square,       color: 'text-gotu-muted',    badge: 'gotu-badge-gray'  },
  completed: { icon: CheckCircle,  color: 'text-gotu-success',  badge: 'gotu-badge-green' },
  failed:    { icon: AlertCircle,  color: 'text-gotu-danger',   badge: 'gotu-badge-red'   },
};

function InvCard({ inv, onStop, onDelete }) {
  const cfg = STATUS_CONFIG[inv.status] ?? STATUS_CONFIG.pending;
  const Icon = cfg.icon;
  return (
    <div className="gotu-card hover:border-gotu-accent hover:border-opacity-40 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`gotu-badge ${cfg.badge}`}>{inv.status}</span>
            <span className="text-xs text-gotu-muted font-mono">{inv.indicator_type}</span>
          </div>
          <h3 className="text-sm font-semibold text-gotu-text truncate">{inv.title}</h3>
          <p className="text-xs text-gotu-muted mt-0.5 font-mono truncate">{inv.indicator}</p>
        </div>
        <Icon size={16} className={cfg.color + " flex-shrink-0 mt-0.5"} />
      </div>
      <div className="mt-3 pt-3 border-t border-gotu-border flex items-center justify-between">
        <div className="flex gap-3 text-xs text-gotu-muted">
          <span>{inv.finding_count ?? 0} findings</span>
          <span>{inv.lead_count ?? 0} leads</span>
        </div>
        <div className="flex gap-2">
          <Link to={`/investigations/${inv.id}`}
            className="text-xs text-gotu-muted hover:text-gotu-accent transition-colors flex items-center gap-1">
            <Eye size={12} /> View
          </Link>
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { investigations, loading, listInvestigations } = useInvestigationStore();
  useEffect(() => { listInvestigations(); }, []);

  const stats = {
    total:     investigations.length,
    running:   investigations.filter(i => i.status === 'running').length,
    completed: investigations.filter(i => i.status === 'completed').length,
    findings:  investigations.reduce((s, i) => s + (i.finding_count ?? 0), 0),
  };

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-gotu-text">Intelligence Dashboard</h1>
          <p className="text-sm text-gotu-muted mt-0.5">Active and completed OSINT investigations</p>
        </div>
        <Link to="/investigations/new" className="gotu-btn-primary flex items-center gap-2">
          <Plus size={14} /> New Investigation
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[{ label: 'Total', value: stats.total, color: 'text-gotu-text' },
          { label: 'Running', value: stats.running, color: 'text-gotu-accent' },
          { label: 'Completed', value: stats.completed, color: 'text-gotu-success' },
          { label: 'Findings', value: stats.findings, color: 'text-gotu-warning' }]
          .map(s => (
            <div key={s.label} className="gotu-card text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-xs text-gotu-muted mt-1">{s.label}</div>
            </div>
          ))}
      </div>

      {/* Investigations grid */}
      {loading ? (
        <div className="text-center py-12 text-gotu-muted">Loading investigations...</div>
      ) : investigations.length === 0 ? (
        <div className="text-center py-16">
          <div className="text-gotu-muted mb-2">No investigations yet</div>
          <Link to="/investigations/new" className="text-sm text-gotu-accent hover:underline">Start your first investigation</Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {investigations.map(inv => <InvCard key={inv.id} inv={inv} />)}
        </div>
      )}
    </div>
  );
}
