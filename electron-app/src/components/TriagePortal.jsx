import React from 'react';
import { motion } from 'framer-motion';
import { useStore, CATEGORIES } from '../store';

export default function TriagePortal() {
  const { selectCategory, collapse } = useStore();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* Header */}
      <div style={{
        padding: '16px 20px 12px',
        borderBottom: '1px solid rgba(255,255,255,0.07)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 10,
            background: 'linear-gradient(135deg, #ff3b30, #ff6b35)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 14, boxShadow: '0 4px 12px rgba(255,59,48,0.4)',
          }}>🛡️</div>
          <div>
            <p style={{ color: '#fff', fontWeight: 700, fontSize: 13, lineHeight: 1.2 }}>Guardian</p>
            <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: 11 }}>Signalement d'incident</p>
          </div>
        </div>
        <button
          onClick={collapse}
          style={{
            background: 'rgba(255,255,255,0.07)', border: 'none', borderRadius: 8,
            width: 28, height: 28, color: 'rgba(255,255,255,0.5)',
            cursor: 'pointer', fontSize: 13, display: 'flex',
            alignItems: 'center', justifyContent: 'center',
            transition: 'background 0.15s',
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.12)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.07)'}
        >✕</button>
      </div>

      {/* Question */}
      <div style={{ padding: '14px 20px 10px' }}>
        <p style={{ color: 'rgba(255,255,255,0.9)', fontWeight: 600, fontSize: 14 }}>Que s'est-il passé ?</p>
        <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: 12, marginTop: 2 }}>Sélectionnez la catégorie correspondante</p>
      </div>

      {/* Categories */}
      <div style={{ padding: '0 16px 14px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, flex: 1 }}>
        {CATEGORIES.map((cat, i) => (
          <motion.button
            key={cat.id}
            onClick={() => selectCategory(cat)}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05, type: 'spring', stiffness: 400, damping: 28 }}
            whileHover={{ scale: 1.04, y: -2 }}
            whileTap={{ scale: 0.96 }}
            style={{
              background: `${cat.color}14`,
              border: `1px solid ${cat.color}35`,
              borderRadius: 14,
              padding: '12px 6px',
              cursor: 'pointer',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 6,
              transition: 'border-color 0.15s, background 0.15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = `${cat.color}28`; e.currentTarget.style.borderColor = `${cat.color}65`; }}
            onMouseLeave={e => { e.currentTarget.style.background = `${cat.color}14`; e.currentTarget.style.borderColor = `${cat.color}35`; }}
          >
            <span style={{ fontSize: 24, lineHeight: 1 }}>{cat.icon}</span>
            <span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 10, fontWeight: 500, lineHeight: 1.3, textAlign: 'center' }}>
              {cat.label}
            </span>
          </motion.button>
        ))}
      </div>

      {/* Footer */}
      <div style={{
        margin: '0 16px 16px',
        padding: '10px 14px',
        borderRadius: 12,
        background: 'rgba(255,255,255,0.04)',
        border: '1px solid rgba(255,255,255,0.07)',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      }}>
        <span style={{ fontSize: 13 }}>🔒</span>
        <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: 10.5, lineHeight: 1.4 }}>
          Données protégées. Signaler un incident n'entraîne aucune sanction.
        </p>
      </div>
    </div>
  );
}
