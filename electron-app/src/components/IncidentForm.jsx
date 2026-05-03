import React from 'react';
import { motion } from 'framer-motion';
import { useStore } from '../store';

export default function IncidentForm() {
  const { selectedCategory, formData, updateForm, submit, submitting, error, setStep } = useStore();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* Header */}
      <div style={{
        padding: '16px 20px 12px',
        borderBottom: '1px solid rgba(255,255,255,0.07)',
        display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <button
          onClick={() => setStep('triage')}
          style={{ background: 'rgba(255,255,255,0.07)', border: 'none', borderRadius: 8,
            width: 28, height: 28, color: 'rgba(255,255,255,0.5)', cursor: 'pointer',
            fontSize: 14, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.12)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.07)'}
        >&#8592;</button>
        <span style={{ fontSize: 22 }}>{selectedCategory?.icon}</span>
        <div>
          <p style={{ color: '#fff', fontWeight: 700, fontSize: 13 }}>{selectedCategory?.label}</p>
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: 11 }}>Confirmez et envoyez</p>
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14, flex: 1 }}>

        {/* Anonymous toggle */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 14px', borderRadius: 12,
          background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <div>
            <p style={{ color: 'rgba(255,255,255,0.85)', fontSize: 13, fontWeight: 500 }}>Signalement anonyme</p>
            <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: 11, marginTop: 2 }}>Votre nom ne sera pas transmis</p>
          </div>
          <div
            onClick={() => updateForm('anonymous', !formData.anonymous)}
            style={{
              width: 40, height: 22, borderRadius: 11, cursor: 'pointer', position: 'relative',
              background: formData.anonymous ? '#3b82f6' : 'rgba(255,255,255,0.15)',
              transition: 'background 0.2s', flexShrink: 0,
            }}
          >
            <motion.div
              animate={{ left: formData.anonymous ? 20 : 3 }}
              transition={{ type: 'spring', stiffness: 500, damping: 30 }}
              style={{ position: 'absolute', top: 3, width: 16, height: 16,
                borderRadius: '50%', background: '#fff',
                boxShadow: '0 1px 4px rgba(0,0,0,0.3)' }}
            />
          </div>
        </div>

        {/* Error */}
        {error && (
          <div style={{ padding: '10px 14px', borderRadius: 10,
            background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)',
            color: '#fca5a5', fontSize: 12 }}>
            Erreur : {error}
          </div>
        )}

        {/* Submit */}
        <motion.button
          onClick={() => { if (!submitting) submit(); }}
          disabled={submitting}
          whileHover={!submitting ? { scale: 1.02 } : {}}
          whileTap={!submitting ? { scale: 0.98 } : {}}
          style={{
            padding: '13px', borderRadius: 14, border: 'none', cursor: submitting ? 'not-allowed' : 'pointer',
            color: '#fff', fontWeight: 700, fontSize: 13, letterSpacing: 0.2,
            background: submitting ? '#3a3a3c' : ('linear-gradient(135deg, ' + (selectedCategory?.color ?? '#ff3b30') + ', ' + (selectedCategory?.color ?? '#ff3b30') + 'cc)'),
            boxShadow: submitting ? 'none' : ('0 6px 20px ' + (selectedCategory?.color ?? '#ff3b30') + '50'),
            opacity: submitting ? 0.6 : 1, transition: 'opacity 0.2s',
            marginTop: 'auto',
          }}
        >
          {submitting ? 'Envoi en cours...' : 'Envoyer le signalement'}
        </motion.button>
      </div>
    </div>
  );
}
