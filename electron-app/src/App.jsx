import React, { useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import FloatingButton from './components/FloatingButton';
import TriagePortal from './components/TriagePortal';
import IncidentForm from './components/IncidentForm';
import ChecklistView from './components/ChecklistView';
import { useStore } from './store';

export default function App() {
  const { step, loadSystemInfo } = useStore();
  const expanded = step !== 'bar';

  useEffect(() => { loadSystemInfo(); }, []);

  return (
    <div style={{ width: '100vw', height: '100vh', background: 'transparent', position: 'relative', overflow: 'hidden' }}>

      {/* Panel — fills window above the button */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            className="panel"
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 64,
              overflow: 'hidden',
              display: 'flex',
              flexDirection: 'column',
            }}
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.15 }}
          >
            {step === 'triage'    && <TriagePortal />}
            {step === 'form'      && <IncidentForm />}
            {step === 'checklist' && <ChecklistView />}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Button — always at bottom-right, 64×64 */}
      <div style={{ position: 'absolute', bottom: 0, right: 0, width: 64, height: 64, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <FloatingButton expanded={expanded} />
      </div>
    </div>
  );
}
