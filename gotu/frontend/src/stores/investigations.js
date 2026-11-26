/**
 * GOTU Investigations Store (Zustand)
 */

import { create } from 'zustand';
import { api } from '../api/client.js';

export const useInvestigationStore = create((set, get) => ({
  investigations: [],
  current:        null,
  findings:       [],
  leads:          [],
  graph:          { nodes: [], edges: [] },
  timeline:       [],
  loading:        false,
  error:          null,

  async listInvestigations() {
    set({ loading: true, error: null });
    try {
      const res = await api.investigations.list();
      set({ investigations: res.data.items, loading: false });
    } catch (err) {
      set({ error: err.response?.data?.error ?? 'Failed to load', loading: false });
    }
  },

  async createInvestigation(data) {
    set({ error: null });
    try {
      const res = await api.investigations.create(data);
      set(state => ({ investigations: [res.data, ...state.investigations] }));
      return { success: true, investigation: res.data };
    } catch (err) {
      const msg = err.response?.data?.error ?? 'Failed to create';
      set({ error: msg });
      return { error: msg };
    }
  },

  async loadInvestigation(id) {
    set({ loading: true, error: null, current: null });
    try {
      const [inv, findings, leads, graph, timeline] = await Promise.allSettled([
        api.investigations.get(id),
        api.investigations.findings(id),
        api.investigations.leads(id),
        api.investigations.graph(id),
        api.investigations.timeline(id),
      ]);
      set({
        current:  inv.status === 'fulfilled' ? inv.value.data : null,
        findings: findings.status === 'fulfilled' ? findings.value.data.items : [],
        leads:    leads.status === 'fulfilled' ? leads.value.data.items : [],
        graph:    graph.status === 'fulfilled' ? graph.value.data : { nodes: [], edges: [] },
        timeline: timeline.status === 'fulfilled' ? timeline.value.data.events : [],
        loading:  false,
      });
    } catch (err) {
      set({ error: err.response?.data?.error ?? 'Failed to load', loading: false });
    }
  },

  async startInvestigation(id) {
    try {
      await api.investigations.start(id);
      set(state => ({
        current: state.current?.id === id ? { ...state.current, status: 'running' } : state.current,
        investigations: state.investigations.map(i => i.id === id ? { ...i, status: 'running' } : i),
      }));
      return { success: true };
    } catch (err) {
      return { error: err.response?.data?.error ?? 'Failed to start' };
    }
  },

  async stopInvestigation(id) {
    try {
      await api.investigations.stop(id);
      set(state => ({
        current: state.current?.id === id ? { ...state.current, status: 'stopped' } : state.current,
        investigations: state.investigations.map(i => i.id === id ? { ...i, status: 'stopped' } : i),
      }));
      return { success: true };
    } catch (err) {
      return { error: err.response?.data?.error ?? 'Failed to stop' };
    }
  },

  async deleteInvestigation(id) {
    try {
      await api.investigations.delete(id);
      set(state => ({
        investigations: state.investigations.filter(i => i.id !== id),
        current: state.current?.id === id ? null : state.current,
      }));
      return { success: true };
    } catch (err) {
      return { error: err.response?.data?.error ?? 'Failed to delete' };
    }
  },

  clearError() { set({ error: null }); },
}));
