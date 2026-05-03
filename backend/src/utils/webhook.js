const axios = require('axios');

const SEVERITY_COLORS = {
  critical: 0xff0000,   // red
  high:     0xff6600,   // orange
  medium:   0xffcc00,   // yellow
  low:      0x00cc66,   // green
};

const SEVERITY_EMOJI = {
  critical: '🔴',
  high:     '🟠',
  medium:   '🟡',
  low:      '🟢',
};

function buildDeliveryResult({ channel, target, status, responseCode = null, errorMessage = null, payload = null }) {
  return {
    channel,
    target,
    status,
    responseCode,
    errorMessage,
    payload,
  };
}

async function postWebhook({ channel, target, body }) {
  try {
    const response = await axios.post(target, body);
    return buildDeliveryResult({
      channel,
      target,
      status: 'sent',
      responseCode: response.status,
      payload: body,
    });
  } catch (error) {
    return buildDeliveryResult({
      channel,
      target,
      status: 'failed',
      responseCode: error.response?.status || null,
      errorMessage: error.message,
      payload: body,
    });
  }
}

/**
 * Send a webhook notification to configured channels.
 */
async function sendWebhook(incident) {
  const tasks = [];

  const emoji = SEVERITY_EMOJI[incident.severity] || '⚪';
  const title = incident.notificationTitle
    ? `${emoji} ${incident.notificationTitle}`
    : `${emoji} [${incident.severity.toUpperCase()}] New Incident: ${incident.category}`;
  const body = incident.description || incident.note || 'No description provided.';

  // Discord
  if (process.env.WEBHOOK_DISCORD_URL && !process.env.WEBHOOK_DISCORD_URL.includes('YOUR_ID')) {
    tasks.push(
      postWebhook({
        channel: 'discord',
        target: process.env.WEBHOOK_DISCORD_URL,
        body: {
        username: 'Guardian Alert',
        embeds: [{
          title,
          description: body,
          color: SEVERITY_COLORS[incident.severity] || 0x808080,
          fields: [
            { name: 'Category', value: incident.category, inline: true },
            { name: 'Status',   value: incident.status,   inline: true },
            { name: 'Phase',    value: incident.workflow_phase || 'Unknown', inline: true },
            { name: 'Machine',  value: incident.machine_id || 'Unknown', inline: true },
            { name: 'IP',       value: incident.ip_address || 'Unknown', inline: true },
            { name: 'Assignee', value: incident.assigned_user_name || incident.assigned_team || 'Unassigned', inline: true },
            { name: 'ID',       value: incident.id, inline: false },
          ],
          timestamp: new Date().toISOString(),
        }],
      } })
    );
  }

  // Slack
  if (process.env.WEBHOOK_SLACK_URL && !process.env.WEBHOOK_SLACK_URL.includes('YOUR')) {
    tasks.push(
      postWebhook({
        channel: 'slack',
        target: process.env.WEBHOOK_SLACK_URL,
        body: {
          text: `*${title}*\n${body}\n> Category: ${incident.category} | Severity: ${incident.severity} | Phase: ${incident.workflow_phase || 'n/a'} | ID: ${incident.id}`,
        },
      })
    );
  }

  // Microsoft Teams
  if (process.env.WEBHOOK_TEAMS_URL && !process.env.WEBHOOK_TEAMS_URL.includes('YOUR')) {
    tasks.push(
      postWebhook({
        channel: 'teams',
        target: process.env.WEBHOOK_TEAMS_URL,
        body: {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        themeColor: SEVERITY_COLORS[incident.severity]?.toString(16) || '808080',
        summary: title,
        sections: [{
          activityTitle: title,
          activityText: body,
          facts: [
            { name: 'Category', value: incident.category },
            { name: 'Severity', value: incident.severity },
            { name: 'Phase',    value: incident.workflow_phase || 'Unknown' },
            { name: 'Machine',  value: incident.machine_id || 'Unknown' },
            { name: 'Assignee', value: incident.assigned_user_name || incident.assigned_team || 'Unassigned' },
            { name: 'ID',       value: incident.id },
          ],
        }],
      } })
    );
  }

  return Promise.all(tasks);
}

module.exports = { sendWebhook };
