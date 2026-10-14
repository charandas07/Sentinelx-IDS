/**
 * SentinelX API Service
 * Axios-based wrapper for all backend REST endpoints.
 */
import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ── Status & Stats ─────────────────────────────────────────────────
export const getStatus = () => api.get('/api/status').then(r => r.data);
export const getStats = () => api.get('/api/stats').then(r => r.data);

// ── Alerts ────────────────────────────────────────────────────────
export const getAlerts = (params = {}) => api.get('/api/alerts', { params }).then(r => r.data);
export const getAlert = (id) => api.get(`/api/alerts/${id}`).then(r => r.data);
export const updateAlert = (id, data) => api.patch(`/api/alerts/${id}`, data).then(r => r.data);

// ── Traffic ───────────────────────────────────────────────────────
export const getTraffic = (params = {}) => api.get('/api/traffic', { params }).then(r => r.data);
export const getPPSHistory = (n = 60) => api.get('/api/traffic/pps-history', { params: { n } }).then(r => r.data);
export const getProtocols = () => api.get('/api/traffic/protocols').then(r => r.data);

// ── IP Analysis ───────────────────────────────────────────────────
export const getIPAnalysis = (ip) => api.get(`/api/ip/${ip}`).then(r => r.data);
export const getSuspiciousIPs = (limit = 50) => api.get('/api/ip', { params: { limit } }).then(r => r.data);

// ── Detection Rules ───────────────────────────────────────────────
export const getRules = () => api.get('/api/rules').then(r => r.data);
export const updateRule = (id, data) => api.put(`/api/rules/${id}`, data).then(r => r.data);
export const resetRule = (id) => api.post(`/api/rules/${id}/reset`).then(r => r.data);

// ── PCAP ──────────────────────────────────────────────────────────
export const uploadPCAP = (file) => {
  const form = new FormData();
  form.append('file', file);
  return api.post('/api/pcap/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000,
  }).then(r => r.data);
};

// ── Demo Mode ─────────────────────────────────────────────────────
export const startDemo = (mode = 'guided') => api.post('/api/demo/start', null, { params: { mode } }).then(r => r.data);
export const stopDemo = () => api.post('/api/demo/stop').then(r => r.data);
export const getDemoStatus = () => api.get('/api/demo/status').then(r => r.data);
export const clearDemoData = () => api.delete('/api/demo/data').then(r => r.data);
export const simulateAttack = (attackType) => api.post(`/api/demo/attack/${attackType}`).then(r => r.data);

// ── Reports ───────────────────────────────────────────────────────
export const getReport = (days = 7) => api.get('/api/reports', { params: { days } }).then(r => r.data);
export const exportReportJSON = (days = 7) => `${BASE_URL}/api/reports/export/json?days=${days}`;
export const exportReportCSV = (days = 7) => `${BASE_URL}/api/reports/export/csv?days=${days}`;

// ── Capture ───────────────────────────────────────────────────────
export const getInterfaces = () => api.get('/api/capture/interfaces').then(r => r.data);
export const startCapture = (iface) => api.post('/api/capture/start', { iface }).then(r => r.data);
export const stopCapture = () => api.post('/api/capture/stop').then(r => r.data);

// ── Whitelist ─────────────────────────────────────────────────────
export const getWhitelist = () => api.get('/api/whitelist').then(r => r.data);
export const addWhitelist = (ip, comment) => api.post('/api/whitelist', { ip, comment }).then(r => r.data);
export const removeWhitelist = (ip) => api.delete(`/api/whitelist/${ip}`).then(r => r.data);

export default api;
