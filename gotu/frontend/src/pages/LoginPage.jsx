import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/auth.js';
import { Shield, Eye, EyeOff } from 'lucide-react';

export default function LoginPage() {
  const [form, setForm] = useState({ username: '', password: ''  });
  const [token, setToken] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const { login, mfaVerify, mfaPending, error, clearError } = useAuthStore();
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    clearError();
    const result = await login(form.username, form.password);
    setSubmitting(false);
    if (result?.success) navigate('/');
  };

  const handleMfa = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    clearError();
    const result = await mfaVerify(token);
    setSubmitting(false);
    if (result?.success) navigate('/');
  };

  return (
    <div className="min-h-screen bg-gotu-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl bg-gotu-accent bg-opacity-10 border border-gotu-accent border-opacity-30 mb-4">
            <Shield size={32} className="text-gotu-accent" />
          </div>
          <h1 className="text-2xl font-bold text-gotu-text">GOTU</h1>
          <p className="text-sm text-gotu-muted mt-1">Advanced OSINT Intelligence Platform</p>
        </div>
        <div className="gotu-card">
          {!mfaPending ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <h2 className="text-sm font-semibold text-gotu-text">Sign In</h2>
              {error && <div className="text-xs text-gotu-danger bg-gotu-danger bg-opacity-10 border border-gotu-danger border-opacity-30 rounded p-2">{error}</div>}
              <div>
                <label className="gotu-label">Username</label>
                <input className="gotu-input" autoFocus value={form.username}
                  onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />
              </div>
              <div>
                <label className="gotu-label">Password</label>
                <div className="relative">
                  <input className="gotu-input pr-10" type={showPass ? 'text' : 'password'}
                    value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
                  <button type="button" onClick={() => setShowPass(s => !s)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gotu-muted hover:text-gotu-text">
                    {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
              <button className="gotu-btn-primary w-full" type="submit" disabled={submitting}>
                {submitting ? 'Signing in...' : 'Sign In'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleMfa} className="space-y-4">
              <h2 className="text-sm font-semibold text-gotu-text">Two-Factor Authentication</h2>
              <p className="text-xs text-gotu-muted">Enter the 6-digit code from your authenticator app.</p>
              {error && <div className="text-xs text-gotu-danger bg-gotu-danger bg-opacity-10 border border-gotu-danger border-opacity-30 rounded p-2">{error}</div>}
              <div>
                <label className="gotu-label">Authentication Code</label>
                <input className="gotu-input font-mono text-center text-lg tracking-widest" maxLength={8}
                  value={token} onChange={e => setToken(e.target.value)} autoFocus />
              </div>
              <button className="gotu-btn-primary w-full" type="submit" disabled={submitting}>
                {submitting ? 'Verifying...' : 'Verify'}
              </button>
            </form>
          )}
        </div>
        <p className="text-center text-xs text-gotu-muted mt-4">Intelligence is authorised use only</p>
      </div>
    </div>
  );
}
