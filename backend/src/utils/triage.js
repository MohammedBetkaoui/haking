/**
 * Triage engine: derive severity and build remediation checklist
 * based on incident category.
 */

const CATEGORY_CONFIG = {
  ransomware: {
    severity: 'critical',
    checklist: [
      'Débranchez immédiatement votre câble réseau RJ45',
      'Désactivez le Wi-Fi sur votre appareil',
      'Ne redémarrez PAS votre ordinateur',
      'Ne payez aucune rançon — contactez immédiatement l\'équipe IT',
      'Photographiez l\'écran si un message de rançon est affiché',
      'Un technicien arrive à votre bureau — restez disponible',
    ],
  },
  phishing: {
    severity: 'high',
    checklist: [
      'Ne cliquez sur aucun lien supplémentaire dans l\'email',
      'Ne répondez pas à l\'email suspect',
      'Notez l\'adresse d\'expéditeur exacte',
      'Ne fournissez aucun identifiant ou mot de passe',
      'Changez votre mot de passe si vous avez cliqué sur un lien',
      'Transférez l\'email à abuse@guardian.local pour analyse',
    ],
  },
  device_loss: {
    severity: 'high',
    checklist: [
      'Notez l\'heure et le lieu approximatif de la perte',
      'Contactez l\'IT pour désactiver le compte sur l\'appareil',
      'Changez tous les mots de passe synchronisés sur cet appareil',
      'Vérifiez vos accès récents (email, VPN, applications)',
      'Signalez aux autorités si appareil volé (récépissé nécessaire)',
    ],
  },
  data_breach: {
    severity: 'critical',
    checklist: [
      'Identifiez quelles données ont été potentiellement exposées',
      'Ne partagez pas l\'information publiquement avant validation DPO',
      'Changez tous vos mots de passe immédiatement',
      'Documentez les circonstances (quand, comment, quoi)',
      'Le DPO doit être notifié dans les 72h (Loi 18-07)',
    ],
  },
  suspicious_activity: {
    severity: 'medium',
    checklist: [
      'Notez précisément ce que vous avez observé',
      'Ne touchez pas au fichier ou système suspect',
      'Isolez l\'appareil du réseau si l\'activité est toujours en cours',
      'Capturez des screenshots si possible',
      'Attendez les instructions de l\'équipe IT',
    ],
  },
  other: {
    severity: 'low',
    checklist: [
      'Décrivez l\'incident avec le plus de détails possible',
      'Conservez tout élément de preuve (email, fichier, screenshot)',
      'L\'équipe IT analysera votre signalement sous peu',
    ],
  },
};

function triage(category) {
  const config = CATEGORY_CONFIG[category] || CATEGORY_CONFIG.other;
  return {
    severity: config.severity,
    checklist: config.checklist.map((label, i) => ({ step: i + 1, label })),
  };
}

module.exports = { triage };
