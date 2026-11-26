import React, { useState } from 'react';
import { api } from '../api/client.js';
import { useAuthStore } from '../stores/auth.js';
import { Shield, Key, Smartphone, LogOut } from 'lucide-react';

export default function SecurityPage() {
  const { user } = useAuthStore();
  const [enrolling, setEnrolling] = useState(false);
  const [qrCode, setQrCode] = useState(null);
  const [manualEntry, setManualEntry] = useState(null);
  const [confirmToken, setConfirmToken] = useState('');
  const [backupCodes, setBackupCodes] = useState(null);
  const [msg, setMsg] = useState(null);
  const [err, setErr] = useState(null);

  const startEnroll = async () => {
    setErr(null);
    try {
      const r = await api.auth.mfaEnroll();
      setQrCode(r.data.qrCode);
      setManualEntry(r.data.manualEntry);
      setEnrolling(true);
    } catch (e) { setErr(e.response?.data?.error ?? 'Failed to start enrollment'); }
  };

  const confirmEnroll = async () => {
    setErr(null);
    try {
      const r = await api.auth.mfaConfirm({ token: confirmToken });
      setBackupCodes(r.data.backupCodes);
      setEnrolling(false);
      setMsg('MFA enabled. Save your backup codes below — they will not be shown again.');
    } catch (e) { setErr(e.response?.data?.error ?? 'Verification failed'); }
  };

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h1 className="text-xl font-bold text-gotu-text mb-1">Security Settings</h1>
      <p className="text-sm text-gotu-muted mb-6">Account security and authentication</p>

      {msg && <div className="bg-gotu-success bg-opacity-10 border border-gotu-success border-opacity-30 rounded-lg p-3 text-sm text-gotu-success mb-4">{msg}</div>}
      {err && <div className="bg-gotu-danger bg-opacity-10 border border-gotu-danger border-opacity-30 rounded-lg p-3 text-sm text-gotu-danger mb-4">{err}</div>}

      <div className="space-y-4">
        <div className="gotu-card flex items-center gap-3">
          <Shield size={20} className="text-gotu-accent" />
          <div className="flex-1">
            <div className="text-sm font-semibold text-gotu-text">Account</div>
            <div className="text-xs text-gotu-muted">{user?.username} · {user?.role} · MFA: {user?.mfaEnabled ? 'Enabled' : 'Disabled'}</div>
          </div>
        </div>

        <div className="gotu-card space-y-3">
          <div className="flex items-center gap-2">
            <Smartphone size={16} className="text-gotu-accent" />
            <span className="text-sm font-semibold text-gotu-text">Two-Factor Authentication (TOTP)</span>
          </div>
          {!user?.mfaEnabled && !enrolling && !backupCodes && (
            <>
              <p className="text-xs text-gotu-muted">Enable MFA to protect your account with a time-based one-time password from an authenticator app.</p>
              <button className="gotu-btn-primary text-sm" onClick={startEnroll}>Enable MFA</button>
            </>
          )}
          {user?.mfaEnabled && <p className="text-xs text-gotu-success">✓ MFA is enabled on this account.</p>}
          {enrolling && qrCode && (
            <div className="space-y-3">
              <p className="text-xs text-gotu-muted">Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)</p>
              <img src={qrCode} alt="MFA QR Code" className="w-40 h-40 rounded border border-gotu-border" />
              <p className="text-xs text-gotu-muted">Or enter manually: <span className="font-mono text-gotu-accent">{manualEntry}</span></p>
              <div>
                <label className="gotu-label">Verification Code</label>
                <input className="gotu-input font-mono w-40 text-center tracking-widest" maxLength={8}
                  value={confirmToken} onChange={e => setConfirmToken(e.target.value)}
                  placeholder="000000" />
              </div>
              <button className="gotu-btn-primary text-sm" onClick={confirmEnroll}>Confirm & Enable</button>
            </div>
          )}
          {backupCodes && (
            <div className="space-y-2">
              <p className="text-xs text-gotu-warning font-semibold">Save these backup codes now. They will not be shown again.</p>
              <div className="grid grid-cols-2 gap-1">
                {backupCodes.map((c, i) => <code key={i} className="text-xs font-mono bg-gotu-bg px-2 py-1 rounded text-gotu-accent">{c}</code>)}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
