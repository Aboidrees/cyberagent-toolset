import axios from 'axios';
import { extractFindings, severityCounts, severityRank, topSeverity } from './findings.js';

/**
 * Webhook / notification support.
 *
 * Sends a run summary to Slack and/or a generic webhook when a run completes,
 * gated on finding severity. Config is environment-driven (no secrets ship):
 *   - SLACK_WEBHOOK_URL   — Slack incoming-webhook URL
 *   - WEBHOOK_URL         — generic JSON webhook (POST)
 *   - NOTIFY_ON_SEVERITY  — comma list, e.g. "high,critical" (default). Notify
 *                           only when a finding at/above the lowest listed
 *                           severity is present. Use "all" to always notify.
 *
 * Never throws — a notification failure must not fail a recon run.
 */
export async function notify({ report, jsonPath, mdPath } = {}) {
  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  const genericUrl = process.env.WEBHOOK_URL;
  if (!slackUrl && !genericUrl) return { sent: false, reason: 'no webhook configured' };

  // Prefer the catalog-aware findings the runner already computed; fall back to
  // generic extraction for reports that lack the rollup.
  const findings = Array.isArray(report?.findings) ? report.findings : extractFindings(report);
  const counts = severityCounts(findings);
  const top = findings.length ? topSeverity(findings) : null;

  // Severity gate.
  const raw = (process.env.NOTIFY_ON_SEVERITY || 'high,critical').toLowerCase();
  const always = raw.split(',').map(s => s.trim()).includes('all');
  const threshold = always
    ? -Infinity
    : Math.min(...raw.split(',').map(s => s.trim()).map(severityRank));
  const triggered = always || (top !== null && severityRank(top) >= threshold);

  if (!triggered) {
    return { sent: false, reason: `no finding at/above ${raw}`, counts };
  }

  const title = report?.playbook?.title || report?.playbook?.id || 'Recon run';
  const target = report?.vars?.target || 'unknown';
  const summaryLine =
    `*${title}* against \`${target}\` — ` +
    `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`;
  const topFindings = findings.slice(0, 10)
    .map(f => `• [${f.severity.toUpperCase()}] ${f.message} (${f.step})`)
    .join('\n');

  const results = {};

  if (slackUrl) {
    const color = { critical: '#cc0000', high: '#e8590c', medium: '#f08c00', low: '#5c940d', info: '#1971c2' }[top] || '#868e96';
    try {
      await axios.post(slackUrl, {
        text: summaryLine,
        attachments: [{ color, text: topFindings || 'No severity-rated findings.' }],
      }, { timeout: 10000 });
      results.slack = 'ok';
    } catch (e) {
      results.slack = `error: ${e.message}`;
    }
  }

  if (genericUrl) {
    try {
      await axios.post(genericUrl, {
        title, target, topSeverity: top, counts, findings,
        artifacts: { jsonPath, mdPath },
        startedAt: report?.startedAt, endedAt: report?.endedAt,
      }, { timeout: 10000 });
      results.webhook = 'ok';
    } catch (e) {
      results.webhook = `error: ${e.message}`;
    }
  }

  return { sent: true, topSeverity: top, counts, results };
}
