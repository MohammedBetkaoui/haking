import { create } from 'zustand';
import axios from 'axios';
import { connectSocket } from './lib/socket';

// In dev, Vite proxy forwards /api → http://localhost:4000
// In prod (packaged), use the env var
const API = import.meta.env.DEV ? '' : (import.meta.env.VITE_API_URL || 'http://localhost:4000');

export const CATEGORIES = [
  { id: 'phishing',            label: 'Phishing / Email suspect',    icon: '🎣', color: '#ff9500' },
  { id: 'ransomware',          label: 'Ransomware / Chiffrement',    icon: '💀', color: '#ff3b30' },
  { id: 'device_loss',         label: 'Perte / Vol d\'appareil',     icon: '📵', color: '#ff9500' },
  { id: 'data_breach',         label: 'Fuite de données',            icon: '🔓', color: '#ff3b30' },
  { id: 'suspicious_activity', label: 'Activité suspecte',           icon: '👁️', color: '#ffcc00' },
  { id: 'other',               label: 'Autre incident',              icon: '⚠️', color: '#8e8e93' },
];

// step: 'bar' | 'triage' | 'form' | 'checklist' | 'done'
export const useStore = create((set, get) => ({
  step: 'bar',
  selectedCategory: null,
  formData: { title: '', description: '', anonymous: false },
  submitting: false,
  result: null,   // { incident_id, severity, checklist }
  error: null,
  systemInfo: null,
  newDetectionCount: 0,
  latestDetectedIp: null,

  setStep: (step) => set({ step }),

  selectCategory: (category) => {
    set({ selectedCategory: category, step: 'form' });
  },

  updateForm: (field, value) =>
    set((s) => ({ formData: { ...s.formData, [field]: value } })),

  loadSystemInfo: async () => {
    if (window.guardian) {
      const info = await window.guardian.systemInfo();
      set({ systemInfo: info });
    }
  },

  clearDetections: () => set({ newDetectionCount: 0, latestDetectedIp: null }),

  expand: () => {
    if (window.guardian) window.guardian.expand();
    set({ step: 'triage' });
  },

  collapse: () => {
    if (window.guardian) window.guardian.collapse();
    set({ step: 'bar', selectedCategory: null, formData: { title: '', description: '', anonymous: false }, result: null, error: null });
  },

  submit: async () => {
    const { selectedCategory, formData, systemInfo } = get();
    if (!selectedCategory) return;

    set({ submitting: true, error: null });
    try {
      const body = {
        category: selectedCategory.id,
        title: `Incident ${selectedCategory.label}`,
        description: null,
        anonymous: formData.anonymous,
        machine_id: systemInfo?.hostname || null,
        metadata: systemInfo || {},
      };
      const { data } = await axios.post(`${API}/api/report`, body);
      set({ result: data, step: 'checklist', submitting: false });
    } catch (err) {
      set({ error: err.response?.data?.error || 'Erreur de connexion au serveur.', submitting: false });
    }
  },
}));

// ── Listen for new IP detections via socket ──────────────────────────────────
const _socket = connectSocket();
_socket.on('scanner:device_detected', ({ ip }) => {
  useStore.setState((s) => ({
    newDetectionCount: Math.min(99, s.newDetectionCount + 1),
    latestDetectedIp: ip,
  }));
});
