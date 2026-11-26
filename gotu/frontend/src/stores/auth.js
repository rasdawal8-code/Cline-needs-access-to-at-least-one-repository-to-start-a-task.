/**
 * GOTU Auth Store (Zustand)
 */

import { create } from 'zustand';
import { api } from '../api/client.js';

export const useAuthStore = create((set, get) => ({
  user:        null,
  loading:     true,
  mfaPending:  false,
  error:       null,

  async init() {
    try {
      const res = await api.auth.me();
      set({ user: res.data, loading: false });
    } catch {
      set({ user: null, loading: false });
    }
  },

  async login(username, password) {
    set({ error: null });
    try {
      const res = await api.auth.login({ username, password });
      if (res.data.mfaRequired) {
        set({ mfaPending: true });
        return { mfaRequired: true };
      }
      set({ user: res.data, mfaPending: false });
      return { success: true };
    } catch (err) {
      const msg = err.response?.data?.error ?? 'Login failed';
      set({ error: msg });
      return { error: msg };
    }
  },

  async mfaVerify(token) {
    set({ error: null });
    try {
      const res = await api.auth.mfaVerify({ token });
      set({ user: res.data, mfaPending: false });
      return { success: true };
    } catch (err) {
      const msg = err.response?.data?.error ?? 'MFA verification failed';
      set({ error: msg });
      return { error: msg };
    }
  },

  async logout() {
    try { await api.auth.logout(); } catch {}
    set({ user: null, mfaPending: false, error: null });
  },

  clearError() { set({ error: null }); },
}));
