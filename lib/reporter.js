/**
 * Security Assessment Reporter
 * Generates structured JSON and Markdown audit reports.
 * Sanitizes sensitive values (passwords, tokens, PII).
 */

const fs = require('fs');
const path = require('path');
const logger = require('./logger');

/**
 * Sanitizes strings to prevent sensitive credentials or tokens from leaking into reports.
 */
function sanitizeEvidence(text) {
  if (typeof text !== 'string') return text;
  return text
    .replace(/(password|passwd|pwd|secret|token|bearer|authorization)=([^\s&"'<>]+)/gi, '$1=[REDACTED]')
    .replace(/bearer\s+[A-Za-z0-9\-_.]+/gi, 'Bearer [REDACTED]')
    .replace(/eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, '[REDACTED_JWT]');
}

class SecurityReporter {
  constructor(targetUrl, appName = 'Web Application Under Test') {
    this.targetUrl = targetUrl;
    this.appName = appName;
    this.assessmentDate = new Date().toISOString();
    this.testedEndpoints = new Set();
    this.findings = [];
  }

  addEndpoint(endpoint) {
    if (endpoint) this.testedEndpoints.add(endpoint);
  }

  /**
   * Adds a finding to the report.
   * @param {object} finding
   * @param {string} finding.id - Unique Finding ID (e.g., XSS-001)
   * @param {string} finding.category - Category (e.g., Cross-Site Scripting (XSS))
   * @param {'Critical'|'High'|'Medium'|'Low'|'Informational'} finding.severity
   * @param {'Confirmed'|'Potential'|'Secure'} finding.status
   * @param {string} finding.title - Brief finding summary
   * @param {string} finding.endpoint - Tested endpoint or parameter
   * @param {string} finding.method - HTTP method
   * @param {string} finding.evidence - Safe sanitized proof or response snippet
   * @param {string[]} finding.reproduction_steps - Step-by-step reproduction
   * @param {string} finding.impact - Real-world security impact
   * @param {string} finding.remediation - Specific actionable code fix
   * @param {string} [finding.owasp_ref] - OWASP Top 10 reference
   * @param {string} [finding.cwe_ref] - Common Weakness Enumeration ID
   */
  addFinding(finding) {
    const sanitizedFinding = {
      ...finding,
      evidence: sanitizeEvidence(finding.evidence),
      reproduction_steps: (finding.reproduction_steps || []).map(sanitizeEvidence)
    };
    this.findings.push(sanitizedFinding);
  }

  getSummary() {
    const severityCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Informational: 0
    };
    let confirmed = 0;
    let potential = 0;
    let secure = 0;

    for (const f of this.findings) {
      if (severityCounts[f.severity] !== undefined) {
        severityCounts[f.severity]++;
      }
      if (f.status === 'Confirmed') confirmed++;
      else if (f.status === 'Potential') potential++;
      else if (f.status === 'Secure') secure++;
    }

    return {
      total_findings: this.findings.length,
      confirmed,
      potential,
      secure,
      by_severity: severityCounts
    };
  }

  toJSON() {
    return {
      target_application: this.appName,
      target_url: this.targetUrl,
      assessment_date: this.assessmentDate,
      tested_endpoints: Array.from(this.testedEndpoints),
      summary: this.getSummary(),
      findings: this.findings
    };
  }

  toMarkdown() {
    const summary = this.getSummary();
    const confirmedFindings = this.findings.filter(f => f.status === 'Confirmed');
    const potentialFindings = this.findings.filter(f => f.status === 'Potential');
    const secureChecks = this.findings.filter(f => f.status === 'Secure');

    let md = `# Security Assessment Report: ${this.appName}\n\n`;
    md += `**Target URL:** \`${this.targetUrl}\`  \n`;
    md += `**Assessment Date:** ${this.assessmentDate}  \n`;
    md += `**Classification:** Authorized Defensive Assessment  \n\n`;

    md += `## Executive Summary\n\n`;
    md += `| Metric | Count |\n`;
    md += `| :--- | :--- |\n`;
    md += `| **Total Endpoints Tested** | ${this.testedEndpoints.size} |\n`;
    md += `| **Confirmed Vulnerabilities** | **${summary.confirmed}** |\n`;
    md += `| **Potential Findings** | ${summary.potential} |\n`;
    md += `| **Verified Secure Controls** | ${summary.secure} |\n`;
    md += `| **Critical Severity** | ${summary.by_severity.Critical} |\n`;
    md += `| **High Severity** | ${summary.by_severity.High} |\n`;
    md += `| **Medium Severity** | ${summary.by_severity.Medium} |\n`;
    md += `| **Low Severity** | ${summary.by_severity.Low} |\n`;
    md += `| **Informational** | ${summary.by_severity.Informational} |\n\n`;

    md += `## Findings Matrix\n\n`;
    if (this.findings.length === 0) {
      md += `*No findings recorded.*\n\n`;
    } else {
      md += `| ID | Status | Severity | Category | Title | Endpoint |\n`;
      md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
      for (const f of this.findings) {
        md += `| \`${f.id}\` | **${f.status}** | ${f.severity} | ${f.category} | ${f.title} | \`${f.endpoint}\` |\n`;
      }
      md += `\n`;
    }

    if (confirmedFindings.length > 0) {
      md += `## Confirmed Vulnerabilities\n\n`;
      for (const f of confirmedFindings) {
        md += `### [${f.severity}] ${f.id}: ${f.title}\n\n`;
        md += `- **Endpoint:** \`${f.method} ${f.endpoint}\`\n`;
        md += `- **Category:** ${f.category}\n`;
        if (f.owasp_ref) md += `- **OWASP Reference:** ${f.owasp_ref}\n`;
        if (f.cwe_ref) md += `- **CWE:** ${f.cwe_ref}\n`;
        md += `- **Verification Status:** \`${f.status}\`\n\n`;

        md += `#### Security Impact\n${f.impact}\n\n`;

        md += `#### Reproduction Steps\n`;
        for (let i = 0; i < (f.reproduction_steps || []).length; i++) {
          md += `${i + 1}. ${f.reproduction_steps[i]}\n`;
        }
        md += `\n`;

        md += `#### Evidence\n\`\`\`text\n${f.evidence || 'N/A'}\n\`\`\`\n\n`;

        md += `#### Recommended Remediation\n${f.remediation}\n\n`;
        md += `---\n\n`;
      }
    }

    if (potentialFindings.length > 0) {
      md += `## Potential Findings (Requires Manual Review)\n\n`;
      for (const f of potentialFindings) {
        md += `### [${f.severity}] ${f.id}: ${f.title}\n\n`;
        md += `- **Endpoint:** \`${f.method} ${f.endpoint}\`\n`;
        md += `- **Evidence:** \`${f.evidence}\`\n`;
        md += `- **Recommended Action:** ${f.remediation}\n\n`;
      }
    }

    if (secureChecks.length > 0) {
      md += `## Verified Secure Controls\n\n`;
      for (const f of secureChecks) {
        md += `- **[PASS] ${f.id}**: ${f.title} on \`${f.endpoint}\` (${f.category})\n`;
      }
      md += `\n`;
    }

    md += `## Confidentiality & Disclaimer\n\n`;
    md += `This report was generated using the **Website Security Testing Toolkit** for authorized defensive validation. ` +
          `No sensitive passwords, production tokens, or customer personal data were gathered or stored during this assessment.\n`;

    return md;
  }

  saveReports(outputDir = './reports', baseFileName = 'security-assessment-report') {
    const resolvedDir = path.resolve(outputDir);
    if (!fs.existsSync(resolvedDir)) {
      fs.mkdirSync(resolvedDir, { recursive: true });
    }

    const jsonPath = path.join(resolvedDir, `${baseFileName}.json`);
    const mdPath = path.join(resolvedDir, `${baseFileName}.md`);

    fs.writeFileSync(jsonPath, JSON.stringify(this.toJSON(), null, 2), 'utf8');
    fs.writeFileSync(mdPath, this.toMarkdown(), 'utf8');

    logger.info(`Reports saved:`);
    logger.info(`- JSON: ${jsonPath}`);
    logger.info(`- Markdown: ${mdPath}`);

    return { jsonPath, mdPath };
  }
}

module.exports = SecurityReporter;
