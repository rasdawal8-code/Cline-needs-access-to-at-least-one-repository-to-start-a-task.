import React, { useEffect, useState } from 'react';
import { api } from '../api/client.js';
import { CheckCircle, XCircle, AlertCircle, ExternalLink } from 'lucide-react';

const STATUS_ICON = {
  operational:    <CheckCircle size={14} className="text-gotu-success" />,
  not_configured: <XCircle size={14} className="text-gotu-warning" />,
  unsupported:    <AlertCircle size={14} className="text-gotu-muted" />,
  error:          <XCircle size={14} className="text-gotu-danger" />,
  rate_limited:   <AlertCircle size={14} className="text-gotu-warning" />,
};

export default function SourcesPage() {
  const [engines, setEngines] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.engines.list().then(r => { setEngines(r.data.engines); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-xl font-bold text-gotu-text mb-1">Source Management</h1>
      <p className="text-sm text-gotu-muted mb-6">Intelligence engine status and API key requirements</p>

      {loading ? <div className="text-gotu-muted">Loading...</div> : (
        <div className="space-y-3">
          {engines.map(engine => (
            <div key={engine.id} className="gotu-card">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  {STATUS_ICON[engine.status.status] ?? STATUS_ICON.error}
                  <div>
                    <div className="text-sm font-semibold text-gotu-text">{engine.name}</div>
                    <div className="text-xs text-gotu-muted mt-0.5">{engine.status.message}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`gotu-badge ${
                    engine.status.status === 'operational' ? 'gotu-badge-green' :
                    engine.status.status === 'not_configured' ? 'gotu-badge-yellow' :
                    'gotu-badge-gray'}`}>{engine.status.status.replace('_', ' ')}</span>
                </div>
              </div>
              <div className="mt-3 pt-3 border-t border-gotu-border flex flex-wrap gap-3 text-xs text-gotu-muted">
                <span>Accepts: {engine.supportedInputTypes.join(', ')}</span>
                {engine.requiredApiKeys.length > 0 && (
                  <span className="text-gotu-warning">Requires: {engine.requiredApiKeys.join(', ')}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
