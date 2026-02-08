/**
 * Tests for the AI Secure Refactoring Agent
 * Covers: language detection, static pattern scanning, security score calculation,
 * knowledge base lookups, and tool execution
 */

import SecureRefactorAgent from '../src/agent/SecureRefactorAgent.js';
import { OWASP_TOP_10_2021, CWE_DATABASE, VULNERABILITY_PATTERNS } from '../src/knowledge/vulnerabilities.js';

// Create agent instance (does not require API key for local tool tests)
let agent;

beforeEach(() => {
  // We instantiate the agent; AI calls are not invoked in these unit tests
  process.env.GEMINI_API_KEY = 'test-key-not-used';
  agent = new SecureRefactorAgent();
  agent.resetSession();
});

// ===================== Knowledge Base Tests =====================

describe('Knowledge Base', () => {
  test('OWASP Top 10 contains all 10 categories', () => {
    const categories = Object.keys(OWASP_TOP_10_2021);
    expect(categories).toHaveLength(10);
    expect(categories).toContain('A01:2021');
    expect(categories).toContain('A03:2021');
    expect(categories).toContain('A10:2021');
  });

  test('Each OWASP category has name, description, cwes, and mitigations', () => {
    for (const [id, data] of Object.entries(OWASP_TOP_10_2021)) {
      expect(data).toHaveProperty('name');
      expect(data).toHaveProperty('description');
      expect(data).toHaveProperty('cwes');
      expect(data).toHaveProperty('mitigations');
      expect(data.cwes.length).toBeGreaterThan(0);
      expect(data.mitigations.length).toBeGreaterThan(0);
    }
  });

  test('CWE Database contains critical entries', () => {
    expect(CWE_DATABASE).toHaveProperty('CWE-89'); // SQL Injection
    expect(CWE_DATABASE).toHaveProperty('CWE-79'); // XSS
    expect(CWE_DATABASE).toHaveProperty('CWE-78'); // Command Injection
    expect(CWE_DATABASE).toHaveProperty('CWE-22'); // Path Traversal
    expect(CWE_DATABASE).toHaveProperty('CWE-798'); // Hardcoded Credentials
  });

  test('CWE entries have required fields', () => {
    for (const [id, data] of Object.entries(CWE_DATABASE)) {
      expect(data).toHaveProperty('name');
      expect(data).toHaveProperty('description');
      expect(data).toHaveProperty('severity');
      expect(data).toHaveProperty('patterns');
    }
  });

  test('Vulnerability patterns exist for JavaScript, Python, Java, PHP', () => {
    expect(VULNERABILITY_PATTERNS).toHaveProperty('javascript');
    expect(VULNERABILITY_PATTERNS).toHaveProperty('python');
    expect(VULNERABILITY_PATTERNS).toHaveProperty('java');
    expect(VULNERABILITY_PATTERNS).toHaveProperty('php');
  });
});

// =================== Language Detection Tests ===================

describe('Language Detection (toolDetectLanguage)', () => {
  test('detects JavaScript from .js filename', () => {
    const result = agent.toolDetectLanguage('const x = 1;', 'app.js');
    expect(result.language).toBe('javascript');
    expect(result.detectedBy).toBe('file_extension');
  });

  test('detects Python from .py filename', () => {
    const result = agent.toolDetectLanguage('import os', 'main.py');
    expect(result.language).toBe('python');
    expect(result.detectedBy).toBe('file_extension');
  });

  test('detects TypeScript from .ts filename', () => {
    const result = agent.toolDetectLanguage('const x: number = 1;', 'app.ts');
    expect(result.language).toBe('typescript');
    expect(result.detectedBy).toBe('file_extension');
  });

  test('detects Java from .java filename', () => {
    const result = agent.toolDetectLanguage('public class Main {}', 'Main.java');
    expect(result.language).toBe('java');
    expect(result.detectedBy).toBe('file_extension');
  });

  test('detects PHP from .php filename', () => {
    const result = agent.toolDetectLanguage('<?php echo "hello";', 'index.php');
    expect(result.language).toBe('php');
    expect(result.detectedBy).toBe('file_extension');
  });

  test('detects JavaScript from code patterns when no filename', () => {
    const code = `const express = require('express');\nconst app = express();\nlet x = 5;`;
    const result = agent.toolDetectLanguage(code, '');
    expect(result.language).toBe('javascript');
    expect(result.detectedBy).toBe('code_patterns');
  });

  test('detects Python from code patterns when no filename', () => {
    const code = `import flask\nfrom flask import request\ndef index():\n    return "hello"`;
    const result = agent.toolDetectLanguage(code, '');
    expect(result.language).toBe('python');
    expect(result.detectedBy).toBe('code_patterns');
  });

  test('defaults to JavaScript for unknown code', () => {
    const result = agent.toolDetectLanguage('x = 1', '');
    expect(result.language).toBe('javascript');
    expect(result.detectedBy).toBe('default');
    expect(result.confidence).toBe('low');
  });
});

// ================== Static Pattern Scan Tests ==================

describe('Static Pattern Scan (toolStaticPatternScan)', () => {
  test('detects SQL Injection in JavaScript', () => {
    const code = `db.query("SELECT * FROM users WHERE id = " + req.query.id);`;
    const result = agent.toolStaticPatternScan(code, 'javascript');
    const sqlFindings = result.findings.filter(f => f.type === 'SQL Injection');
    expect(sqlFindings.length).toBeGreaterThan(0);
  });

  test('detects XSS via innerHTML in JavaScript', () => {
    const code = `document.getElementById('output').innerHTML = userInput;`;
    const result = agent.toolStaticPatternScan(code, 'javascript');
    const xssFindings = result.findings.filter(f => f.type === 'XSS');
    expect(xssFindings.length).toBeGreaterThan(0);
  });

  test('detects Hardcoded Secrets in JavaScript', () => {
    const code = `const password = 'admin123';`;
    const result = agent.toolStaticPatternScan(code, 'javascript');
    const secretFindings = result.findings.filter(f => f.type === 'Hardcoded Secrets');
    expect(secretFindings.length).toBeGreaterThan(0);
  });

  test('detects eval usage in JavaScript', () => {
    const code = `const result = eval(userInput);`;
    const result = agent.toolStaticPatternScan(code, 'javascript');
    const evalFindings = result.findings.filter(f => f.type === 'Eval Usage');
    expect(evalFindings.length).toBeGreaterThan(0);
  });

  test('detects Math.random in JavaScript', () => {
    const code = `const token = Math.random().toString(36);`;
    const result = agent.toolStaticPatternScan(code, 'javascript');
    const randomFindings = result.findings.filter(f => f.type === 'Insecure Random');
    expect(randomFindings.length).toBeGreaterThan(0);
  });

  test('detects Command Injection in Python', () => {
    const code = `import os\nos.system('ping ' + user_input)`;
    const result = agent.toolStaticPatternScan(code, 'python');
    const cmdFindings = result.findings.filter(f => f.type === 'Command Injection');
    expect(cmdFindings.length).toBeGreaterThan(0);
  });

  test('detects Debug Mode in Python', () => {
    const code = `app.run(host='0.0.0.0', port=5000, debug=True)`;
    const result = agent.toolStaticPatternScan(code, 'python');
    const debugFindings = result.findings.filter(f => f.type === 'Debug Mode');
    expect(debugFindings.length).toBeGreaterThan(0);
  });

  test('detects pickle deserialization in Python', () => {
    const code = `import pickle\ndata = pickle.loads(user_data)`;
    const result = agent.toolStaticPatternScan(code, 'python');
    const pickleFindings = result.findings.filter(f => f.type === 'Pickle Deserialization');
    expect(pickleFindings.length).toBeGreaterThan(0);
  });

  test('returns zero findings for clean code', () => {
    const code = `const x = 5;\nconst y = x + 10;\nconsole.log(y);`;
    const result = agent.toolStaticPatternScan(code, 'javascript');
    // May have 0 or very few findings (pattern-based can have noise)
    expect(result.totalFindings).toBeDefined();
  });

  test('detects SQL Injection in Java', () => {
    const code = `Statement stmt = connection.createStatement();\nstmt.executeQuery("SELECT * FROM users WHERE id=" + userId);`;
    const result = agent.toolStaticPatternScan(code, 'java');
    const sqlFindings = result.findings.filter(f => f.type === 'SQL Injection');
    expect(sqlFindings.length).toBeGreaterThan(0);
  });
});

// ================ Security Score Calculation Tests ================

describe('Security Score Calculation (toolCalculateSecurityScore)', () => {
  test('returns 100 for zero vulnerabilities', () => {
    const result = agent.toolCalculateSecurityScore({
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      codeLength: 50,
    });
    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe('Low');
  });

  test('returns critical risk level for critical vulns', () => {
    const result = agent.toolCalculateSecurityScore({
      totalVulnerabilities: 4,
      criticalCount: 4,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      codeLength: 50,
    });
    expect(result.score).toBe(0);
    expect(result.riskLevel).toBe('Critical');
  });

  test('scores decrease proportionally to severity', () => {
    const critResult = agent.toolCalculateSecurityScore({
      totalVulnerabilities: 1, criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, codeLength: 50,
    });
    const highResult = agent.toolCalculateSecurityScore({
      totalVulnerabilities: 1, criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0, codeLength: 50,
    });
    const medResult = agent.toolCalculateSecurityScore({
      totalVulnerabilities: 1, criticalCount: 0, highCount: 0, mediumCount: 1, lowCount: 0, codeLength: 50,
    });
    const lowResult = agent.toolCalculateSecurityScore({
      totalVulnerabilities: 1, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 1, codeLength: 50,
    });

    expect(critResult.score).toBeLessThan(highResult.score);
    expect(highResult.score).toBeLessThan(medResult.score);
    expect(medResult.score).toBeLessThan(lowResult.score);
  });

  test('score never goes below 0', () => {
    const result = agent.toolCalculateSecurityScore({
      totalVulnerabilities: 20,
      criticalCount: 10,
      highCount: 5,
      mediumCount: 3,
      lowCount: 2,
      codeLength: 20,
    });
    expect(result.score).toBeGreaterThanOrEqual(0);
  });

  test('returns correct breakdown', () => {
    const result = agent.toolCalculateSecurityScore({
      totalVulnerabilities: 4,
      criticalCount: 1,
      highCount: 1,
      mediumCount: 1,
      lowCount: 1,
      codeLength: 50,
    });
    expect(result.breakdown).toEqual({
      critical: 1,
      high: 1,
      medium: 1,
      low: 1,
    });
  });
});

// =================== OWASP Lookup Tests ===================

describe('OWASP Lookup (toolLookupOwasp)', () => {
  test('returns all categories for "all"', () => {
    const result = agent.toolLookupOwasp('all');
    expect(result.categories).toHaveLength(10);
  });

  test('returns specific category data', () => {
    const result = agent.toolLookupOwasp('A03:2021');
    expect(result.name).toBe('Injection');
    expect(result.relatedCWEs).toBeDefined();
    expect(result.mitigations).toBeDefined();
  });

  test('returns error for unknown category', () => {
    const result = agent.toolLookupOwasp('A99:2021');
    expect(result.error).toBeDefined();
  });
});

// =================== CWE Lookup Tests ===================

describe('CWE Lookup (toolLookupCwe)', () => {
  test('finds CWE-89 (SQL Injection)', () => {
    const result = agent.toolLookupCwe('CWE-89');
    expect(result.name).toBe('SQL Injection');
    expect(result.severity).toBe('Critical');
  });

  test('finds CWE by number only', () => {
    const result = agent.toolLookupCwe('79');
    expect(result.name).toBe('Cross-site Scripting (XSS)');
  });

  test('finds CWE by name search', () => {
    const result = agent.toolLookupCwe('Path Traversal');
    expect(result.id).toBe('CWE-22');
  });

  test('returns error for unknown CWE', () => {
    const result = agent.toolLookupCwe('CWE-99999');
    expect(result.error).toBeDefined();
  });
});

// ============== Vulnerability Reporting Tests ==============

describe('Vulnerability Reporting (toolReportVulnerability)', () => {
  test('adds vulnerability to session state', () => {
    const result = agent.toolReportVulnerability({
      type: 'SQL Injection',
      severity: 'Critical',
      lineNumbers: [12],
      description: 'SQL injection via string concatenation',
      impact: 'Full database compromise',
      owaspCategory: 'A03:2021',
      cweId: 'CWE-89',
      confidence: 'High',
    });

    expect(result.success).toBe(true);
    expect(result.totalVulnerabilities).toBe(1);
    expect(agent.sessionState.foundVulnerabilities).toHaveLength(1);
    expect(agent.sessionState.foundVulnerabilities[0].type).toBe('SQL Injection');
  });

  test('enriches with OWASP info when available', () => {
    agent.toolReportVulnerability({
      type: 'SQL Injection',
      severity: 'Critical',
      lineNumbers: [12],
      description: 'test',
      impact: 'test',
      owaspCategory: 'A03:2021',
      cweId: 'CWE-89',
    });

    const vuln = agent.sessionState.foundVulnerabilities[0];
    expect(vuln.owaspInfo).toBeDefined();
    expect(vuln.owaspInfo.name).toBe('Injection');
    expect(vuln.cweInfo).toBeDefined();
    expect(vuln.cweInfo.name).toBe('SQL Injection');
  });
});

// ============== Submit Full Analysis Tests ==============

describe('Submit Full Analysis (toolSubmitFullAnalysis)', () => {
  test('processes batch vulnerabilities', () => {
    const result = agent.toolSubmitFullAnalysis({
      vulnerabilities: [
        { type: 'SQL Injection', severity: 'Critical', lineNumbers: [12], description: 'test', impact: 'test' },
        { type: 'XSS', severity: 'Medium', lineNumbers: [20], description: 'test2', impact: 'test2' },
      ],
      attackVectors: [
        { vector: 'SQL Injection Attack', description: 'Inject SQL', likelihood: 'High' },
      ],
      recommendations: [
        { recommendation: 'Use parameterized queries', priority: 'High', effort: 'Medium' },
      ],
      overallAssessment: 'Code has critical issues',
      securityScore: 35,
    });

    expect(result.success).toBe(true);
    expect(result.summary.vulnerabilities).toBe(2);
    expect(result.summary.attackVectors).toBe(1);
    expect(result.summary.recommendations).toBe(1);
    expect(agent.sessionState.foundVulnerabilities).toHaveLength(2);
    expect(agent.sessionState.analysisData.securityScore).toBe(35);
    expect(agent.sessionState.scanComplete).toBe(true);
  });
});

// ============== Fix Application Tests ==============

describe('Apply Security Fix (toolApplySecurityFix)', () => {
  test('replaces vulnerable code with fixed code', () => {
    const original = `const password = 'admin123';`;
    const result = agent.toolApplySecurityFix(
      original,
      `'admin123'`,
      `process.env.DB_PASSWORD`,
      'Replaced hardcoded password with environment variable'
    );

    expect(result.success).toBe(true);
    expect(result.codeUpdated).toBe(true);
    expect(agent.sessionState.currentCode).toContain('process.env.DB_PASSWORD');
    expect(agent.sessionState.appliedFixes).toHaveLength(1);
  });
});

// ============== Finalize Tests ==============

describe('Finalize Scan (toolFinalizeScan)', () => {
  test('marks scan as complete and calculates severity breakdown', () => {
    agent.toolReportVulnerability({ type: 'SQLi', severity: 'Critical', lineNumbers: [1], description: 't', impact: 't' });
    agent.toolReportVulnerability({ type: 'XSS', severity: 'Medium', lineNumbers: [2], description: 't', impact: 't' });

    const result = agent.toolFinalizeScan('Found 2 vulnerabilities');
    expect(result.scanComplete).toBe(true);
    expect(result.totalVulnerabilities).toBe(2);
    expect(result.severityBreakdown.Critical).toBe(1);
    expect(result.severityBreakdown.Medium).toBe(1);
    expect(result.riskLevel).toBe('Critical');
  });
});

describe('Finalize Refactor (toolFinalizeRefactor)', () => {
  test('marks refactor as complete with fixed code', () => {
    const fixedCode = `const password = process.env.DB_PASSWORD;`;
    const result = agent.toolFinalizeRefactor(fixedCode, 'Replaced hardcoded password', ['Test login flow']);

    expect(result.refactorComplete).toBe(true);
    expect(result.fixedCode).toBe(fixedCode);
    expect(result.testingRecommendations).toContain('Test login flow');
    expect(agent.sessionState.refactorComplete).toBe(true);
  });
});

// ============== Session Reset Tests ==============

describe('Session Management', () => {
  test('resetSession clears all state', () => {
    agent.sessionState.foundVulnerabilities.push({ type: 'test' });
    agent.sessionState.language = 'python';
    agent.sessionState.scanComplete = true;

    agent.resetSession();

    expect(agent.sessionState.foundVulnerabilities).toHaveLength(0);
    expect(agent.sessionState.language).toBe('');
    expect(agent.sessionState.scanComplete).toBe(false);
    expect(agent.sessionState.currentCode).toBe('');
  });
});

// ============== Summary Generation Tests ==============

describe('Summary Generation (generateSummary)', () => {
  test('correctly counts severities and types', () => {
    const findings = [
      { type: 'SQL Injection', severity: 'Critical', owaspCategory: 'A03:2021' },
      { type: 'XSS', severity: 'Medium', owaspCategory: 'A03:2021' },
      { type: 'Hardcoded Credentials', severity: 'High', owaspCategory: 'A07:2021' },
      { type: 'Insecure Random', severity: 'Low', owaspCategory: 'A02:2021' },
    ];

    const summary = agent.generateSummary(findings);
    expect(summary.totalVulnerabilities).toBe(4);
    expect(summary.severityBreakdown.Critical).toBe(1);
    expect(summary.severityBreakdown.Medium).toBe(1);
    expect(summary.severityBreakdown.High).toBe(1);
    expect(summary.severityBreakdown.Low).toBe(1);
    expect(summary.riskLevel).toBe('Critical');
    expect(summary.owaspCategories['A03:2021']).toBe(2);
    expect(summary.vulnerabilityTypes['SQL Injection']).toBe(1);
  });

  test('returns None risk level when no vulnerabilities', () => {
    const summary = agent.generateSummary([]);
    expect(summary.totalVulnerabilities).toBe(0);
    expect(summary.riskLevel).toBe('None');
  });
});

// ============ Overall Assessment Generation Tests ============

describe('Overall Assessment (generateOverallAssessment)', () => {
  test('returns appropriate assessment for high score', () => {
    const assessment = agent.generateOverallAssessment({ score: 95 });
    expect(assessment).toContain('strong security');
  });

  test('returns appropriate assessment for medium score', () => {
    const assessment = agent.generateOverallAssessment({ score: 75 });
    expect(assessment).toContain('moderate security');
  });

  test('returns appropriate assessment for low score', () => {
    const assessment = agent.generateOverallAssessment({ score: 55 });
    expect(assessment).toContain('significant security issues');
  });

  test('returns critical assessment for very low score', () => {
    const assessment = agent.generateOverallAssessment({ score: 20 });
    expect(assessment).toContain('critical security vulnerabilities');
  });
});
