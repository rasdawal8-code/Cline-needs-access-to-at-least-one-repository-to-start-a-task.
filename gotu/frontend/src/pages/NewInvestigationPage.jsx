import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useInvestigationStore } from '../stores/investigations.js';
import { Search, AlertCircle } from 'lucide-react';

const INDICATOR_TYPES = [
  { value: 'username',     label: 'Username' },
  { value: 'email',        label: 'Email Address' },
  { value: 'domain',       label: 'Domain' },
  { value: 'url',          label: 'URL' },
  { value: 'name',         label: 'Full Name' },
  { value: 'organization', label: 'Organization' },
  { value: 'ip',           label: 'IP Address' },
  { value: 'phone',        label: 'Phone Number' },
  { value: 'other',        label: 'Other' },
];

export default function NewInvestigationPage() {
  const navigate = useNavigate();
  const { createInvestigation } = useInvestigationStore();
  const [form, setForm] = useState({
    title: '', indicator: '', indicatorType: 'username',
    maxDepth: 2, maxDurationSeconds: 600, maxApiCalls: 500, requireLeadApproval: false,
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.title || !form.indicator) { setError('Title and indicator are required.'); return; }
    setSubmitting(true); setError(null);
    const result = await createInvestigation(form);
    setSubmitting(false);
    if (result.success) navigate(`/investigations/${result.investigation.id}`);
    else setError(result.error);
  };

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h1 className="text-xl font-bold text-gotu-text mb-1">New Investigation</h1>
      <p className="text-sm text-gotu-muted mb-6">Configure your OSINT investigation parameters</p>

      {error && (
        <div className="flex items-center gap-2 text-sm text-gotu-danger bg-gotu-danger bg-opacity-10 border border-gotu-danger border-opacity-30 rounded-lg p-3 mb-4">
          <AlertCircle size={14} className="flex-shrink-0" />{error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="gotu-card space-y-4">
          <h2 className="text-sm font-semibold text-gotu-text">Investigation Target</h2>
          <div>
            <label className="gotu-label">Investigation Title</label>
            <input className="gotu-input" placeholder="e.g. Investigate username johndoe123"
              value={form.title} onChange={e => set('title', e.target.value)} />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-1">
              <label className="gotu-label">Indicator Type</label>
              <select className="gotu-input" value={form.indicatorType} onChange={e => set('indicatorType', e.target.value)}>
                {INDICATOR_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
            <div className="col-span-2">
              <label className="gotu-label">Indicator Value</label>
              <input className="gotu-input font-mono" placeholder="Enter the target indicator"
                value={form.indicator} onChange={e => set('indicator', e.target.value)} />
            </div>
          </div>
        </div>

        <div className="gotu-card space-y-4">
          <h2 className="text-sm font-semibold text-gotu-text">Investigation Controls</h2>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="gotu-label">Max Depth (1-5)</label>
              <input type="number" className="gotu-input" min={1} max={5}
                value={form.maxDepth} onChange={e => set('maxDepth', +e.target.value)} />
            </div>
            <div>
              <label className="gotu-label">Max Duration (s)</label>
              <input type="number" className="gotu-input" min={60} max={3600}
                value={form.maxDurationSeconds} onChange={e => set('maxDurationSeconds', +e.target.value)} />
            </div>
            <div>
              <label className="gotu-label">Max API Calls</label>
              <input type="number" className="gotu-input" min={10} max={5000}
                value={form.maxApiCalls} onChange={e => set('maxApiCalls', +e.target.value)} />
            </div>
          </div>
          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" className="w-4 h-4 accent-gotu-accent"
              checked={form.requireLeadApproval} onChange={e => set('requireLeadApproval', e.target.checked)} />
            <div>
              <div className="text-sm text-gotu-text">Require manual lead approval</div>
              <div className="text-xs text-gotu-muted">Review and approve discovered leads before they are investigated</div>
            </div>
          </label>
        </div>

        <div className="flex gap-3">
          <button type="submit" className="gotu-btn-primary flex items-center gap-2" disabled={submitting}>
            <Search size={14} />
            {submitting ? 'Creating...' : 'Create Investigation'}
          </button>
          <button type="button" className="gotu-btn-secondary" onClick={() => navigate('/')}>Cancel</button>
        </div>
      </form>
    </div>
  );
}
