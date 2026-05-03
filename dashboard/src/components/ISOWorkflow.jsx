import React, { useState } from 'react';
import { Check, X } from 'lucide-react';
import { updatePhase } from '../lib/api';

const PHASES = [
  { id: 'detect',  label: 'Detect',  icon: '🔍', textClass: 'text-blue-400',    ringClass: 'ring-blue-500',    connClass: 'bg-blue-500/40'    },
  { id: 'report',  label: 'Report',  icon: '📋', textClass: 'text-amber-400',   ringClass: 'ring-amber-500',   connClass: 'bg-amber-500/40'   },
  { id: 'assess',  label: 'Assess',  icon: '⚖️',  textClass: 'text-rose-400',    ringClass: 'ring-rose-500',    connClass: 'bg-rose-500/40'    },
  { id: 'respond', label: 'Respond', icon: '🛡️', textClass: 'text-purple-400',  ringClass: 'ring-purple-500',  connClass: 'bg-purple-500/40'  },
  { id: 'learn',   label: 'Learn',   icon: '📚', textClass: 'text-emerald-400', ringClass: 'ring-emerald-500', connClass: 'bg-emerald-500/40' },
];

const PHASE_IDS = PHASES.map(p => p.id);

const PHASE_HINTS = {
  detect:  'Décrivez comment l\'incident a été détecté…',
  report:  'Décrivez les informations collectées et enregistrées…',
  assess:  'Décrivez l\'évaluation de sévérité effectuée…',
  respond: 'Décrivez les actions de containment et d\'éradication…',
  learn:   'Décrivez le bilan post-incident et les recommandations…',
};

export default function ISOWorkflow({ incidentId, currentPhase, onTransition }) {
  const [modalPhase, setModalPhase] = useState(null);
  const [comment, setComment]       = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState('');

  const currentIdx = PHASE_IDS.indexOf(currentPhase || 'assess');

  const openModal = (phase, idx) => {
    if (idx !== currentIdx + 1) return;
    setModalPhase(phase);
    setComment('');
    setError('');
  };

  const closeModal = () => {
    if (submitting) return;
    setModalPhase(null);
  };

  const handleConfirm = async () => {
    if (!comment.trim()) {
      setError('Le commentaire est obligatoire pour enregistrer la transition.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await updatePhase(incidentId, modalPhase.id, comment.trim());
      setModalPhase(null);
      setComment('');
      onTransition?.();
    } catch (e) {
      setError(e?.response?.data?.error || 'Erreur lors de la transition de phase.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      {/* ── Timeline ─────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between select-none pt-2 pb-6">
        {PHASES.map((phase, idx) => {
          const isCompleted = idx < currentIdx;
          const isCurrent   = idx === currentIdx;
          const isNext      = idx === currentIdx + 1;
          const isFuture    = idx > currentIdx + 1;

          return (
            <React.Fragment key={phase.id}>
              {/* Node + label */}
              <div className="flex flex-col items-center gap-2 relative">
                <button
                  onClick={() => openModal(phase, idx)}
                  disabled={!isNext}
                  title={isNext ? `Passer en phase ${phase.label}` : undefined}
                  className={[
                    'w-10 h-10 rounded-full flex items-center justify-center text-base transition-all duration-200',
                    isCompleted ? 'ring-2 ring-emerald-500 bg-emerald-500/15' : '',
                    isCurrent   ? `ring-2 ${phase.ringClass} bg-gray-800 shadow-lg shadow-black/40` : '',
                    isNext      ? `ring-1 ring-gray-600 bg-gray-800 hover:ring-2 hover:${phase.ringClass} cursor-pointer hover:scale-110 hover:bg-gray-700` : '',
                    isFuture    ? 'ring-1 ring-gray-800 bg-gray-900 opacity-35 cursor-default' : '',
                  ].filter(Boolean).join(' ')}
                >
                  {isCompleted
                    ? <Check size={15} className="text-emerald-400" />
                    : <span>{phase.icon}</span>
                  }
                </button>

                <span className={`text-xs font-medium leading-tight text-center ${
                  isCompleted ? 'text-emerald-400'  :
                  isCurrent   ? phase.textClass      :
                  isNext      ? 'text-gray-400'      :
                                'text-gray-700'
                }`}>
                  {phase.label}
                </span>

                {isCurrent && (
                  <span className={`absolute -bottom-4 text-[10px] font-semibold ${phase.textClass} whitespace-nowrap`}>
                    ● Actuel
                  </span>
                )}
                {isNext && (
                  <span className="absolute -bottom-4 text-[10px] text-gray-600 whitespace-nowrap">
                    ↑ Cliquer
                  </span>
                )}
              </div>

              {/* Connector */}
              {idx < PHASES.length - 1 && (
                <div className="flex-1 h-px mt-5 mx-1">
                  <div className={`h-full transition-all duration-500 ${
                    idx < currentIdx ? 'bg-emerald-500/50' : 'bg-gray-800'
                  }`} />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* ── Transition Modal ─────────────────────────────────────────────── */}
      {modalPhase && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
          onClick={(e) => { if (e.target === e.currentTarget) closeModal(); }}
        >
          <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-md shadow-2xl mx-4">
            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-gray-100 font-semibold text-base leading-tight">
                  Transition de phase ISO 27035
                </h3>
                <p className="text-gray-500 text-sm mt-1">
                  <span className="text-gray-400">
                    {PHASES[currentIdx]?.icon} {PHASES[currentIdx]?.label}
                  </span>
                  <span className="mx-2 text-gray-600">→</span>
                  <span className={`font-medium ${modalPhase.textClass}`}>
                    {modalPhase.icon} {modalPhase.label}
                  </span>
                </p>
              </div>
              <button onClick={closeModal} className="btn-ghost p-1.5 -mt-1 -mr-1">
                <X size={16} />
              </button>
            </div>

            {/* Comment field */}
            <label className="block text-gray-400 text-xs font-medium mb-1.5">
              Commentaire <span className="text-red-400 ml-0.5">*</span>
            </label>
            <textarea
              autoFocus
              value={comment}
              onChange={(e) => { setComment(e.target.value); setError(''); }}
              placeholder={PHASE_HINTS[modalPhase.id]}
              rows={4}
              className="w-full bg-gray-800 border border-gray-700 rounded-xl px-3 py-2.5 text-gray-200 text-sm resize-none focus:outline-none focus:border-gray-500 placeholder-gray-600 transition-colors"
            />
            {error && (
              <p className="text-red-400 text-xs mt-1.5 flex items-center gap-1">
                <span>⚠</span> {error}
              </p>
            )}

            {/* Info note */}
            <p className="text-gray-600 text-xs mt-2">
              Cette transition sera enregistrée de façon immuable dans le journal d'audit (ISO 27001).
            </p>

            {/* Actions */}
            <div className="flex gap-3 mt-4">
              <button
                onClick={handleConfirm}
                disabled={submitting}
                className="flex-1 btn-primary disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {submitting ? 'Enregistrement…' : 'Confirmer la transition'}
              </button>
              <button
                onClick={closeModal}
                disabled={submitting}
                className="btn-ghost px-4"
              >
                Annuler
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
