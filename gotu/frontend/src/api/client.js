/**
 * GOTU API Client
 * Axios instance with CSRF token injection and session management.
 */

import axios from 'axios';

const client = axios.create({
  baseURL: '/api',
  withCredentials: true,
  timeout: 30000,
});

// CSRF token management
let _csrfToken = null;

async function fetchCsrfToken() {
  const res = await axios.get('/api/csrf-token', { withCredentials: true });
  _csrfToken = res.data.csrfToken;
  return _csrfToken;
}

// Request interceptor: inject CSRF token on mutations
client.interceptors.request.use(async (config) => {
  const method = config.method?.toLowerCase();
  if (['post', 'put', 'patch', 'delete'].includes(method)) {
    if (!_csrfToken) await fetchCsrfToken();
    config.headers['x-csrf-token'] = _csrfToken;
  }
  return config;
});

// Response interceptor: handle 401 (session expired) and 403 (CSRF)
client.interceptors.response.use(
  res => res,
  async (error) => {
    if (error.response?.status === 403 && error.config && !error.config._csrfRetried) {
      // CSRF token expired — refresh and retry once
      await fetchCsrfToken();
      error.config._csrfRetried = true;
      error.config.headers['x-csrf-token'] = _csrfToken;
      return client(error.config);
    }
    if (error.response?.status === 401) {
      // Session expired — redirect to login
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// API methods
export const api = {
  // Auth
  auth: {
    register:    (data) => client.post('/auth/register', data),
    login:       (data) => client.post('/auth/login', data),
    mfaVerify:   (data) => client.post('/auth/mfa/verify', data),
    mfaBackup:   (data) => client.post('/auth/mfa/backup', data),
    mfaEnroll:   ()     => client.post('/auth/mfa/enroll'),
    mfaConfirm:  (data) => client.post('/auth/mfa/confirm', data),
    logout:      ()     => client.post('/auth/logout'),
    me:          ()     => client.get('/auth/me'),
  },

  // Investigations
  investigations: {
    create:       (data)       => client.post('/investigations', data),
    list:         (params)     => client.get('/investigations', { params }),
    get:          (id)         => client.get(`/investigations/${id}`),
    start:        (id)         => client.post(`/investigations/${id}/start`),
    pause:        (id)         => client.post(`/investigations/${id}/pause`),
    resume:       (id)         => client.post(`/investigations/${id}/resume`),
    stop:         (id)         => client.post(`/investigations/${id}/stop`),
    delete:       (id)         => client.delete(`/investigations/${id}`),
    leads:        (id, params) => client.get(`/investigations/${id}/leads`, { params }),
    approveLead:  (id, lid)    => client.post(`/investigations/${id}/leads/${lid}/approve`),
    rejectLead:   (id, lid)    => client.post(`/investigations/${id}/leads/${lid}/reject`),
    findings:     (id)         => client.get(`/investigations/${id}/findings`),
    graph:        (id)         => client.get(`/investigations/${id}/graph`),
    timeline:     (id)         => client.get(`/investigations/${id}/timeline`),
  },

  // Engines
  engines: {
    list:   ()   => client.get('/engines'),
    get:    (id) => client.get(`/engines/${id}`),
  },
};

export { fetchCsrfToken };
export default client;
