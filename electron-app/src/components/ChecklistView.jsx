import React from 'react';
import { motion } from 'framer-motion';
import { useStore } from '../store';

const SEV = {
  critical: { color: '#ff3b30', label: 'CRITIQUE' },
  high:     { color: '#ff9500', label: 'ELEVE' },
  medium:   { color: '#ffcc00', label: 'MOYEN' },
  low:      { color: '#34c759', label: 'FAIBLE' },
};

export default function ChecklistView() {
  const { result, collapse } = useStore();
  const severity = result?.severity || 'medium';
  const sev = SEV[severity] || SEV.medium;
  const checklist = result?.checklist || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflowY: 'auto' }}>

      <div style={{ padding: '16px 20px 12px', borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 700, color: sev.color, letterSpacing: 0.5 }}>{sev.label}</span>
            <p style={{ color: '#fff', fontWeight: 700, fontSize: 13, marginTop: 2 }}>Incident signale</p>
            <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: 11, marginTop: 2 }}>ID : {result?.incident_id?.slice(0, 8)}...</p>
          </div>
          <div style={{
            width: 44, height: 44, borderRadius: 14, fontSize: 20,
            background: sev.color + '20', border: '1px solid ' + sev.color + '40',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>&#128737;</div>
        </div>
      </div>

      <div style={{ padding: '14px 16px', flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <p style={{ color: 'rgba(255,255,255,0.6)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 4 }}>Actions immediates</p>
        {checklist.map((item, i) => (
          <motion.div
            key={item.step}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.06, type: 'spring', stiffness: 350, damping: 26 }}
            style={{
              display: 'flex', alignItems: 'flex-start', gap: 10,
              padding: '10px 12px', borderRadius: 10,
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)',
            }}
          >
            <span style={{ color: sev.color, fontWeight: 700, fontSize: 11, marginTop: 1, minWidth: 16 }}>{i + 1}.</span>
            <span style={{ color: 'rgba(255,255,255,0.8)', fontSize: 12, lineHeight: 1.5 }}>{item.label}</span>
          </motion.div>
        ))}
      </div>

      <div style={{ padding: '0 16px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{
          padding: '10px 14px', borderRadius: 12,
          background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.25)',
        }}>
          <p style={{ color: '#93c5fd', fontSize: 11, textAlign: 'center' }}>
            Un technicien a ete alerte et arrive a votre bureau.
          </p>
        </div>
        <button
          onClick={collapse}
          style={{
            padding: '11px', borderRadius: 12, border: '1px solid rgba(255,255,255,0.1)',
            background: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.55)',
            fontSize: 12, cursor: 'pointer', fontWeight: 500,
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.1)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.06)'}
        >Fermer</button>
      </div>
    </div>
  );
}
