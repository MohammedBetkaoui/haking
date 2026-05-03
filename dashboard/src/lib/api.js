import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:4000',
  timeout: 10000,
});

export const fetchIncidents = (params = {}) =>
  api.get('/api/incidents', { params }).then(r => r.data);

export const fetchStats = () =>
  api.get('/api/incidents/stats').then(r => r.data);

export const fetchIncident = (id) =>
  api.get(`/api/incidents/${id}`).then(r => r.data);

export const fetchAssignableUsers = () =>
  api.get('/api/users/assignees').then(r => r.data);

export const updateStatus = (id, status, note, actor_id) =>
  api.patch(`/api/incidents/${id}/status`, { status, note, actor_id }).then(r => r.data);

export const assignIncident = (id, payload) =>
  api.patch(`/api/incidents/${id}/assignment`, payload).then(r => r.data);

export const exportIncident = (id) =>
  api.get(`/api/incidents/${id}/export`).then(r => r.data);

export const updateChecklist = (incidentId, step, completed) =>
  api.patch(`/api/incidents/${incidentId}/checklist/${step}`, { completed }).then(r => r.data);

export const updatePhase = (id, toPhase, comment, actor_id) =>
  api.put(`/api/incidents/${id}/phase`, { toPhase, comment, actor_id }).then(r => r.data);

export const fetchMonthlyReports = (limit = 12) =>
  api.get('/api/reports/monthly', { params: { limit } }).then(r => r.data);

export const generateMonthlyReport = (payload = {}) =>
  api.post('/api/reports/monthly/generate', payload).then(r => r.data);

export const fetchNetworkHosts = () =>
  api.get('/api/auto-detect/network/hosts').then(r => r.data);

export const getMonthlyReportDownloadUrl = (id) =>
  `${api.defaults.baseURL}/api/reports/monthly/${id}/download`;

export const fetchDeviceDetails = (ip) =>
  api.get(`/api/device-details/${encodeURIComponent(ip)}`).then(r => r.data);

export const addTrustedDevice = (mac) =>
  api.post('/api/device-details/trust', { mac }).then(r => r.data);

export const fetchCyberAgentReports = (limit = 50) =>
  api.get('/api/cyber-agent/reports', { params: { limit } }).then(r => r.data);

export const fetchCyberAgentIncidents = (limit = 50) =>
  api.get('/api/cyber-agent/incidents', { params: { limit } }).then(r => r.data);

export default api;
