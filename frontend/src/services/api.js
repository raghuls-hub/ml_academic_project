/**
 * API Service for SOC Backend Endpoints
 * Supports single JSON telemetry analysis and multipart/form-data CSV batch uploads.
 */

import axios from 'axios';

// Base API instance with Vite proxy handling
const apiClient = axios.create({
  baseURL: '/api/v1',
  timeout: 35000,
  headers: {
    'Accept': 'application/json',
  },
});

// Response interceptor for consistent error messaging
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error intercepted:', error?.response || error?.message);
    return Promise.reject(error);
  }
);

export const api = {
  /**
   * Health and service readiness check
   */
  async checkHealth() {
    const res = await apiClient.get('/health');
    return res.data;
  },

  /**
   * Fetch default sample telemetry presets
   */
  async getPresets() {
    const res = await apiClient.get('/presets');
    return res.data;
  },

  /**
   * Host Syscall & Payload Security (BETH Module)
   * @param {Object|FormData} payload - Single JSON record or FormData with CSV file
   */
  async analyzeHost(payload) {
    const isFormData = payload instanceof FormData;
    const config = isFormData ? { headers: { 'Content-Type': 'multipart/form-data' } } : {};
    const res = await apiClient.post('/host/analyze', payload, config);
    return res.data;
  },

  /**
   * Network Intrusion Inspector (NSL-KDD Module)
   * @param {Object|FormData} payload - Single JSON flow or FormData with CSV file
   */
  async analyzeNetwork(payload) {
    const isFormData = payload instanceof FormData;
    const config = isFormData ? { headers: { 'Content-Type': 'multipart/form-data' } } : {};
    const res = await apiClient.post('/network/analyze', payload, config);
    return res.data;
  },

  /**
   * Auth & Insider Threat Engine (CERT Module)
   * @param {Object|FormData} payload - Single JSON auth log or FormData with CSV file
   */
  async analyzeAuth(payload) {
    const isFormData = payload instanceof FormData;
    const config = isFormData ? { headers: { 'Content-Type': 'multipart/form-data' } } : {};
    const res = await apiClient.post('/auth/analyze', payload, config);
    return res.data;
  },

  /**
   * On-Demand Incident Report Generation via Groq LLM
   */
  async generateIncidentReport(threatData, context = 'SOC Operator Investigation') {
    const res = await apiClient.post('/incident/report', {
      threat_data: threatData,
      context,
    });
    return res.data;
  },
};

export default api;

