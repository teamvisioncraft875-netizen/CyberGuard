const nodemailer = require('nodemailer');
const db = require('../config/db');

const SENSITIVE_KEY_REGEX = /password|token|secret|authorization|cookie|bearer|hash/i;
const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://localhost:3000';
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:5000';

// Check email configuration on module load
const hasSendGrid = Boolean(process.env.SENDGRID_API_KEY);
const hasSmtp = Boolean(process.env.SMTP_HOST);

if (!hasSendGrid && !hasSmtp) {
  console.warn('[NotificationService] No email provider configured (missing SENDGRID_API_KEY or SMTP_HOST). Automated email notifications are in simulation mode.');
}

/**
 * Strips any sensitive credentials (passwords, tokens, cookies, auth headers)
 * from objects before including them in notification bodies.
 */
function sanitizeForNotification(data, depth = 0) {
  if (depth > 5 || data === null || data === undefined) {
    return data;
  }
  if (typeof data === 'string') {
    return data.length > 500 ? `${data.slice(0, 500)}...[truncated]` : data;
  }
  if (Array.isArray(data)) {
    return data.map((item) => sanitizeForNotification(item, depth + 1));
  }
  if (typeof data === 'object') {
    const clean = {};
    for (const [key, value] of Object.entries(data)) {
      if (SENSITIVE_KEY_REGEX.test(key)) {
        continue; // Scrub completely
      }
      clean[key] = sanitizeForNotification(value, depth + 1);
    }
    return clean;
  }
  return data;
}

/**
 * Builds the notification email subject and text/html body.
 */
function formatActionEmail(action = {}, incident = {}, policy = null) {
  const isShadow = action.action_mode === 'shadow';
  const isPendingApproval = action.status === 'pending_approval';

  const threatType = incident.threat_type || 'Unknown Threat';
  const riskScore = incident.risk_score != null ? incident.risk_score : 'N/A';
  const actionType = action.action_type || 'Action';
  const incidentId = incident.id || action.incident_id || 'N/A';
  const actionId = action.id || 'N/A';

  // Scrubbed context
  const cleanExplanation = incident.explanation
    ? sanitizeForNotification(incident.explanation)
    : 'No additional details provided';
  const cleanTarget = action.target ? sanitizeForNotification(action.target) : {};

  // Subject line formatting
  let subject;
  if (isShadow) {
    subject = `[CYBERGUARD ALERT] This is a simulated action: ${actionType} for ${threatType} (Risk: ${riskScore})`;
  } else if (isPendingApproval) {
    subject = `[CYBERGUARD ALERT] Approval Required: ${actionType} for ${threatType} (Risk: ${riskScore})`;
  } else {
    subject = `[CYBERGUARD ALERT] Response Action ${action.status}: ${actionType} for ${threatType} (Risk: ${riskScore})`;
  }

  // Incident and approval links
  const incidentUrl = `${DASHBOARD_URL}/incidents/${incidentId}`;
  const approvalUrl = `${DASHBOARD_URL}/admin/actions/${actionId}/approve`;

  // Plaintext body
  let text = `CYBERGUARD Automated Response Notification\n`;
  text += `═══════════════════════════════════════════════\n\n`;

  if (isShadow) {
    text += `[SIMULATION NOTICE]\n`;
    text += `This is a simulated action. The response policy engine is operating in SHADOW MODE.\n`;
    text += `No disruptive actions have been executed against your environment.\n\n`;
  }

  text += `Threat Summary:\n`;
  text += `- Threat Type: ${threatType}\n`;
  text += `- Risk Score: ${riskScore}/100\n`;
  text += `- Recommended Action: ${actionType}\n`;
  text += `- Action Mode: ${action.action_mode}\n`;
  text += `- Current Status: ${action.status}\n`;
  if (policy && policy.name) {
    text += `- Triggered Policy: ${policy.name}\n`;
  }
  text += `\nDetails:\n${cleanExplanation}\n\n`;
  text += `Target Info: ${JSON.stringify(cleanTarget, null, 2)}\n\n`;
  text += `View Incident in Dashboard: ${incidentUrl}\n`;

  if (isPendingApproval) {
    text += `\n[ACTION REQUIRED: APPROVE / REJECT]\n`;
    text += `This response action requires administrator authorization before execution.\n`;
    text += `Approve Action: ${approvalUrl}\n`;
  }

  // HTML body
  let html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
      <h2 style="color: #0f172a; margin-top: 0;">CYBERGUARD Alert</h2>
  `;

  if (isShadow) {
    html += `
      <div style="background-color: #f1f5f9; border-left: 4px solid #64748b; padding: 12px; margin-bottom: 20px; border-radius: 4px;">
        <strong style="color: #334155;">Simulated Action Notice:</strong>
        <p style="margin: 4px 0 0 0; color: #475569; font-size: 14px;">This is a simulated action in shadow mode. No live system actions were executed.</p>
      </div>
    `;
  }

  html += `
    <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
      <tr><td style="padding: 6px 0; color: #64748b; width: 160px;">Threat Type:</td><td style="padding: 6px 0; font-weight: 600; color: #0f172a;">${threatType}</td></tr>
      <tr><td style="padding: 6px 0; color: #64748b;">Risk Score:</td><td style="padding: 6px 0; font-weight: 600; color: #ef4444;">${riskScore} / 100</td></tr>
      <tr><td style="padding: 6px 0; color: #64748b;">Recommended Action:</td><td style="padding: 6px 0; font-weight: 600; color: #0f172a;">${actionType}</td></tr>
      <tr><td style="padding: 6px 0; color: #64748b;">Action Mode:</td><td style="padding: 6px 0; color: #0f172a;">${action.action_mode}</td></tr>
      <tr><td style="padding: 6px 0; color: #64748b;">Status:</td><td style="padding: 6px 0; color: #0f172a;">${action.status}</td></tr>
    </table>

    <div style="background: #f8fafc; padding: 12px; border-radius: 6px; margin-bottom: 20px;">
      <strong style="color: #334155; font-size: 14px;">Details:</strong>
      <p style="margin: 6px 0 0 0; color: #475569; font-size: 14px;">${cleanExplanation}</p>
    </div>

    <div style="margin: 25px 0 10px 0;">
      <a href="${incidentUrl}" style="background-color: #2563eb; color: #ffffff; padding: 10px 18px; text-decoration: none; border-radius: 6px; font-weight: 500; display: inline-block;">View Incident in Dashboard</a>
  `;

  if (isPendingApproval) {
    html += `
      <a href="${approvalUrl}" style="background-color: #16a34a; color: #ffffff; padding: 10px 18px; text-decoration: none; border-radius: 6px; font-weight: 500; display: inline-block; margin-left: 10px;">Approve Action</a>
    `;
  }

  html += `
    </div>
    <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0 15px 0;" />
    <p style="color: #94a3b8; font-size: 12px; margin: 0;">CYBERGUARD Autonomous Security Operations</p>
  </div>`;

  return { subject, text, html };
}

const notificationService = {
  formatActionEmail,

  /**
   * Generic alert email dispatcher supporting SendGrid (preferred) and SMTP (Nodemailer).
   * Returns true/false and never throws.
   *
   * @param {string} toEmail
   * @param {string} subject
   * @param {string} body
   * @param {string|null} [html=null]
   * @returns {Promise<boolean>}
   */
  async sendAlertEmail(toEmail, subject, body, html = null) {
    if (!toEmail) return false;

    try {
      // 1. SendGrid (Preferred if configured)
      if (process.env.SENDGRID_API_KEY) {
        const fromEmail = process.env.SENDGRID_FROM || process.env.SMTP_FROM || 'alerts@cyberguard.security';
        const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${process.env.SENDGRID_API_KEY}`
          },
          body: JSON.stringify({
            personalizations: [{ to: [{ email: toEmail }] }],
            from: { email: fromEmail, name: 'CYBERGUARD Security' },
            subject,
            content: [
              { type: 'text/plain', value: body },
              ...(html ? [{ type: 'text/html', value: html }] : [])
            ]
          })
        });

        if (response.ok || response.status === 202) {
          return true;
        } else {
          const errText = await response.text();
          console.error('[SendGrid Notification Error]', response.status, errText);
          return false;
        }
      }

      // 2. SMTP via Nodemailer
      if (process.env.SMTP_HOST) {
        const transporter = nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port: parseInt(process.env.SMTP_PORT || '587', 10),
          secure: process.env.SMTP_SECURE === 'true',
          auth: process.env.SMTP_USER ? {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
          } : undefined
        });

        const from = process.env.SMTP_FROM || '"CYBERGUARD Alert" <alerts@cyberguard.security>';
        await transporter.sendMail({
          from,
          to: toEmail,
          subject,
          text: body,
          html: html || undefined
        });

        return true;
      }

      // 3. Fallback dev mode (no provider configured)
      // Notifications simply won't send; log once
      return false;
    } catch (err) {
      console.error('[NotificationService Email Error]', err.message);
      return false;
    }
  },

  /**
   * Sends action notification to organization administrator(s).
   * Fire-and-forget: wraps in try/catch, logs error, never throws.
   *
   * @param {Object} action
   * @param {Object} incident
   * @param {Object|null} policy
   * @returns {Promise<boolean>}
   */
  async sendActionNotification(action, incident, policy = null) {
    try {
      if (!action) return false;

      // 1. Locate organization administrator recipient
      let adminEmail = null;
      if (action.organization_id) {
        const adminRes = await db.query(
          `SELECT email FROM public.users WHERE organization_id = $1 AND role = 'admin' ORDER BY created_at ASC LIMIT 1;`,
          [action.organization_id]
        );
        if (adminRes.rows.length > 0) {
          adminEmail = adminRes.rows[0].email;
        }
      }

      // Fallback recipient if organization lookup yields no user
      if (!adminEmail) {
        adminEmail = process.env.ALERT_ADMIN_EMAIL || 'admin@cyberguard.internal';
      }

      // 2. Format email
      const { subject, text, html } = formatActionEmail(action, incident, policy);

      // 3. Dispatch email
      return await this.sendAlertEmail(adminEmail, subject, text, html);
    } catch (err) {
      console.error('[NotificationService sendActionNotification Error]', err.message);
      return false;
    }
  },

  /**
   * Sends confirmation email when an admin approves or rejects an action.
   *
   * @param {Object} action
   * @param {Object} approverUser
   * @param {boolean} approved
   * @returns {Promise<boolean>}
   */
  async sendApprovalConfirmation(action, approverUser, approved) {
    try {
      if (!approverUser || !approverUser.email) return false;

      const decision = approved ? 'APPROVED' : 'REJECTED';
      const subject = `[CYBERGUARD] Response Action ${decision}: ${action.action_type}`;
      const body = `Administrator ${approverUser.email} has ${decision.toLowerCase()} response action ${action.id} (${action.action_type}).\nTimestamp: ${new Date().toISOString()}`;

      return await this.sendAlertEmail(approverUser.email, subject, body);
    } catch (err) {
      console.error('[NotificationService sendApprovalConfirmation Error]', err.message);
      return false;
    }
  }
};

module.exports = notificationService;
