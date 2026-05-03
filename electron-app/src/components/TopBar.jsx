import React from 'react';
import { motion } from 'framer-motion';
import { useStore } from '../store';

export default function TopBar() {
  const { expand, step } = useStore();

  return (
    <motion.div
      className="glass drag-region w-full flex items-center justify-between px-4"
      style={{ height: 56 }}
      initial={{ opacity: 0, y: -56 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut' }}
    >
      {/* Brand */}
      <div className="flex items-center gap-2 select-none">
        <span className="text-lg">🛡️</span>
        <span className="text-white font-semibold text-sm tracking-wide">Guardian</span>
        <span className="text-xs text-white/40 font-normal">Incident Reporter</span>
      </div>

      {/* Status dots */}
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
        <span className="text-white/50 text-xs">Connecté</span>
      </div>

      {/* OOPS Button */}
      <motion.button
        onClick={expand}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        className="flex items-center gap-2 px-4 py-1.5 rounded-full text-sm font-bold text-white shadow-lg"
        style={{
          background: 'linear-gradient(135deg, #ff3b30, #ff6b35)',
          boxShadow: '0 0 20px rgba(255,59,48,0.5)',
        }}
      >
        <span>⚡</span>
        <span>Signaler un incident</span>
      </motion.button>
    </motion.div>
  );
}
