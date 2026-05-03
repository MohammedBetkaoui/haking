export const SEVERITY_LABELS = {
  critical: { label: 'Critique', className: 'badge-critical', dot: 'bg-red-500' },
  high:     { label: 'Élevé',    className: 'badge-high',     dot: 'bg-orange-500' },
  medium:   { label: 'Moyen',    className: 'badge-medium',   dot: 'bg-yellow-500' },
  low:      { label: 'Faible',   className: 'badge-low',      dot: 'bg-green-500' },
};

export const STATUS_LABELS = {
  open:        { label: 'Ouvert',      className: 'status-open' },
  in_progress: { label: 'En cours',    className: 'status-in_progress' },
  mitigating:  { label: 'Mitigation',  className: 'status-mitigating' },
  closed:      { label: 'Fermé',       className: 'status-closed' },
};

export const CATEGORY_LABELS = {
  phishing:            { label: 'Phishing',         icon: '🎣' },
  ransomware:          { label: 'Ransomware',        icon: '💀' },
  device_loss:         { label: 'Perte appareil',    icon: '📵' },
  data_breach:         { label: 'Fuite données',     icon: '🔓' },
  suspicious_activity: { label: 'Activité suspecte', icon: '👁️' },
  other:               { label: 'Autre',             icon: '⚠️' },
};

export const NEXT_STATUS = {
  open:        'in_progress',
  in_progress: 'mitigating',
  mitigating:  'closed',
  closed:      null,
};

export const NEXT_STATUS_LABEL = {
  open:        'Prendre en charge',
  in_progress: 'Démarrer mitigation',
  mitigating:  'Fermer incident',
  closed:      null,
};

export const WORKFLOW_PHASE_LABELS = {
  detect:  { label: 'Detect', className: 'phase-detect' },
  report:  { label: 'Report', className: 'phase-report' },
  assess:  { label: 'Assess', className: 'phase-assess' },
  respond: { label: 'Respond', className: 'phase-respond' },
  learn:   { label: 'Learn', className: 'phase-learn' },
};

export const WORKFLOW_STATE_LABELS = {
  active:    { label: 'Actif', className: 'status-open' },
  completed: { label: 'Terminé', className: 'status-closed' },
  breached:  { label: 'SLA dépassé', className: 'sla-breached' },
  warning:   { label: 'SLA proche', className: 'sla-warning' },
};
