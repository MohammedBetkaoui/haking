const axios = require('axios');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const pool = require('../db/pool');
const { sendWebhook } = require('../utils/webhook');

function parseRecipients(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildEventLabel(eventType) {
  switch (eventType) {
    case 'incident_reported':
      return 'New incident reported';
    case 'incident_escalated':
      return 'Incident escalated automatically';
    case 'monthly_report_generated':
      return 'Monthly compliance report generated';
    default:
      return eventType;
  }
}

function shouldSendSms(eventType, severity) {
  if (eventType === 'monthly_report_generated') {
    return false;
  }

  return eventType === 'incident_escalated' || ['critical', 'high'].includes(severity);
}

function shouldSendWebhook(eventType) {
  return eventType !== 'monthly_report_generated';
}

function shouldSendEmail(_eventType, _severity) {
  return true;
}

function buildNotificationText({ eventType, incident, report }) {
  if (eventType === 'monthly_report_generated') {
    return {
      title: `Monthly report ready: ${report.summary?.month || report.report_month}`,
      text: `The monthly compliance report for ${report.summary?.month || report.report_month} is ready. File: ${report.storage_path}`,
      sms: `Guardian report ready: ${report.summary?.month || report.report_month}`,
      siemPayload: {
        event_type: eventType,
        timestamp: new Date().toISOString(),
        source: process.env.SIEM_SOURCE || 'guardian',
        report: {
          id: report.id,
          month: report.summary?.month || report.report_month,
          path: report.storage_path,
          status: report.status,
        },
      },
    };
  }

  const phase = incident.workflow_phase || 'n/a';
  const assignee = incident.assigned_user_name || incident.assigned_team || 'Unassigned';
  const title = eventType === 'incident_escalated'
    ? `[${incident.severity?.toUpperCase() || 'MEDIUM'}] Escalation on ${phase}`
    : `[${incident.severity?.toUpperCase() || 'MEDIUM'}] Incident reported: ${incident.category}`;
  const text = [
    buildEventLabel(eventType),
    `Incident: ${incident.title || incident.id}`,
    `Category: ${incident.category}`,
    `Severity: ${incident.severity}`,
    `Phase: ${phase}`,
    `Status: ${incident.status || 'open'}`,
    `Assignee: ${assignee}`,
    incident.note ? `Note: ${incident.note}` : null,
    incident.description ? `Description: ${incident.description}` : null,
  ].filter(Boolean).join('\n');

  return {
    title,
    text,
    sms: `${buildEventLabel(eventType)} | ${incident.category} | ${incident.severity} | ${phase}`,
    siemPayload: {
      event_type: eventType,
      timestamp: new Date().toISOString(),
      source: process.env.SIEM_SOURCE || 'guardian',
      incident: {
        id: incident.id,
        title: incident.title,
        category: incident.category,
        severity: incident.severity,
        status: incident.status,
        workflow_phase: phase,
        workflow_state: incident.workflow_state,
        escalation_level: incident.escalation_level,
        assigned_to: incident.assigned_to,
        assigned_user_name: incident.assigned_user_name,
        assigned_team: incident.assigned_team,
      },
      note: incident.note || null,
    },
  };
}

async function recordDelivery(result, { incidentId = null, severity = null, eventType }) {
  await pool.query(
    `INSERT INTO notification_deliveries
       (id, incident_id, channel, target, severity, event_type, status, response_code, error_message, payload, delivered_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      uuidv4(),
      incidentId,
      result.channel,
      result.target,
      severity,
      eventType,
      result.status,
      result.responseCode,
      result.errorMessage,
      JSON.stringify(result.payload || null),
      result.status === 'sent' ? new Date() : null,
    ]
  );
}

let transporter;

function getMailer() {
  if (!process.env.SMTP_HOST || !process.env.ALERT_EMAIL_TO) {
    return null;
  }

  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER
        ? {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS || '',
          }
        : undefined,
    });
  }

  return transporter;
}

async function sendEmail({ title, text, eventType, incidentId, severity }) {
  if (!shouldSendEmail(eventType, severity)) {
    return [];
  }

  const mailer = getMailer();
  const recipients = parseRecipients(process.env.ALERT_EMAIL_TO);
  if (!mailer || recipients.length === 0) {
    return [];
  }

  try {
    const response = await mailer.sendMail({
      from: process.env.ALERT_EMAIL_FROM || process.env.SMTP_USER || 'guardian@localhost',
      to: recipients.join(', '),
      subject: `[Guardian] ${title}`,
      text,
    });

    return [{
      channel: 'email',
      target: recipients.join(', '),
      status: 'sent',
      responseCode: null,
      errorMessage: null,
      payload: { title, text, eventType, incidentId, messageId: response.messageId },
    }];
  } catch (error) {
    return [{
      channel: 'email',
      target: recipients.join(', '),
      status: 'failed',
      responseCode: null,
      errorMessage: error.message,
      payload: { title, text, eventType, incidentId },
    }];
  }
}

async function sendSms({ message, eventType, incidentId, severity }) {
  if (!shouldSendSms(eventType, severity)) {
    return [];
  }

  const webhookUrl = process.env.SMS_WEBHOOK_URL;
  const recipients = parseRecipients(process.env.ALERT_SMS_TO);
  if (!webhookUrl || recipients.length === 0) {
    return [];
  }

  const headers = {
    'Content-Type': 'application/json',
  };

  if (process.env.SMS_API_KEY) {
    headers[process.env.SMS_AUTH_HEADER || 'Authorization'] = process.env.SMS_AUTH_HEADER ? process.env.SMS_API_KEY : `Bearer ${process.env.SMS_API_KEY}`;
  }

  return Promise.all(recipients.map(async (target) => {
    const payload = {
      to: target,
      from: process.env.SMS_FROM || 'Guardian',
      message,
      event_type: eventType,
      incident_id: incidentId,
      severity,
    };

    try {
      const response = await axios.post(webhookUrl, payload, { headers });
      return {
        channel: 'sms',
        target,
        status: 'sent',
        responseCode: response.status,
        errorMessage: null,
        payload,
      };
    } catch (error) {
      return {
        channel: 'sms',
        target,
        status: 'failed',
        responseCode: error.response?.status || null,
        errorMessage: error.message,
        payload,
      };
    }
  }));
}

async function sendSiem(payload, { eventType, incidentId, severity }) {
  if (!process.env.SIEM_ENDPOINT) {
    return [];
  }

  const headers = {
    'Content-Type': 'application/json',
  };

  if (process.env.SIEM_TOKEN) {
    headers.Authorization = `Bearer ${process.env.SIEM_TOKEN}`;
  }

  try {
    const response = await axios.post(process.env.SIEM_ENDPOINT, payload, { headers });
    return [{
      channel: 'siem',
      target: process.env.SIEM_ENDPOINT,
      status: 'sent',
      responseCode: response.status,
      errorMessage: null,
      payload: { eventType, incidentId, severity, body: payload },
    }];
  } catch (error) {
    return [{
      channel: 'siem',
      target: process.env.SIEM_ENDPOINT,
      status: 'failed',
      responseCode: error.response?.status || null,
      errorMessage: error.message,
      payload: { eventType, incidentId, severity, body: payload },
    }];
  }
}

async function notifyIncidentEvent({ eventType, incident }) {
  const content = buildNotificationText({ eventType, incident });
  const deliveries = [];

  if (shouldSendWebhook(eventType)) {
    deliveries.push(...await sendWebhook({
      ...incident,
      notificationTitle: content.title,
      note: content.text,
    }));
  }

  deliveries.push(...await sendEmail({
    title: content.title,
    text: content.text,
    eventType,
    incidentId: incident.id,
    severity: incident.severity,
  }));
  deliveries.push(...await sendSms({
    message: content.sms,
    eventType,
    incidentId: incident.id,
    severity: incident.severity,
  }));
  deliveries.push(...await sendSiem(content.siemPayload, {
    eventType,
    incidentId: incident.id,
    severity: incident.severity,
  }));

  await Promise.all(deliveries.map((delivery) => recordDelivery(delivery, {
    incidentId: incident.id,
    severity: incident.severity,
    eventType,
  })));

  return deliveries;
}

async function notifyMonthlyReportGenerated({ report }) {
  const content = buildNotificationText({ eventType: 'monthly_report_generated', report });
  const deliveries = [];

  deliveries.push(...await sendEmail({
    title: content.title,
    text: content.text,
    eventType: 'monthly_report_generated',
    incidentId: null,
    severity: null,
  }));
  deliveries.push(...await sendSiem(content.siemPayload, {
    eventType: 'monthly_report_generated',
    incidentId: null,
    severity: null,
  }));

  await Promise.all(deliveries.map((delivery) => recordDelivery(delivery, {
    incidentId: null,
    severity: null,
    eventType: 'monthly_report_generated',
  })));

  return deliveries;
}

module.exports = {
  notifyIncidentEvent,
  notifyMonthlyReportGenerated,
};