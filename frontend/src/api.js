import axios from 'axios';

const BASE = process.env.REACT_APP_API_URL || 'https://phishara-api.onrender.com';

const api = axios.create({ baseURL: BASE });

export const scan = (input_value, input_type = 'auto') =>
  api.post('/api/scan', { input_value, input_type }).then(r => r.data);

export const getHistory = (params = {}) =>
  api.get('/api/history', { params }).then(r => r.data);

export const getStats = () =>
  api.get('/api/stats').then(r => r.data);

export const getScan = (id) =>
  api.get(`/api/scan/${id}`).then(r => r.data);

export const downloadReport = (id, fmt = 'json') =>
  `${BASE}/api/report/${id}?fmt=${fmt}`;

export const headlessScan = (url) =>
  api.post('/api/scan/headless', { url }).then(r => r.data);

export default api;
