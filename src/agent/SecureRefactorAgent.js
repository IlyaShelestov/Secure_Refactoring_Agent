/**
 * AI Secure Refactoring Agent with Function Calling
 * A REAL AI Agent that uses Gemini's function calling capabilities
 * to autonomously analyze, scan, and refactor code for security vulnerabilities
 */

import { GoogleGenerativeAI } from '@google/generative-ai';
import config from '../config/index.js';
import logger from '../utils/logger.js';
import { getAgentInstructions } from './prompts.js';
import { OWASP_TOP_10_2021, CWE_DATABASE, VULNERABILITY_PATTERNS } from '../knowledge/vulnerabilities.js';

/**
 * Tool definitions for the AI Agent
 * These are the functions the agent can call
 * Using string types for schema (compatible with @google/generative-ai v0.21.0+)
 */
const AGENT_TOOLS = [
  {
    name: 'detect_language',
    description: 'Detect the programming language of the given code based on syntax patterns and file extension',
    parameters: {
      type: 'OBJECT',
      properties: {
        code: {
          type: 'STRING',
          description: 'The source code to analyze',
        },
        filename: {
          type: 'STRING',
          description: 'Optional filename with extension',
        },
      },
      required: ['code'],
    },
  },
  {
    name: 'static_pattern_scan',
    description: 'Perform a static pattern-based vulnerability scan using regex patterns for known vulnerability signatures',
    parameters: {
      type: 'OBJECT',
      properties: {
        code: {
          type: 'STRING',
          description: 'The source code to scan',
        },
        language: {
          type: 'STRING',
          description: 'The programming language (javascript, python, java, php, etc.)',
        },
      },
      required: ['code', 'language'],
    },
  },
  {
    name: 'lookup_owasp',
    description: 'Look up OWASP Top 10 2021 information for a specific category or get all categories',
    parameters: {
      type: 'OBJECT',
      properties: {
        category: {
          type: 'STRING',
          description: 'OWASP category ID (e.g., "A01:2021") or "all" for all categories',
        },
      },
      required: ['category'],
    },
  },
  {
    name: 'lookup_cwe',
    description: 'Look up CWE (Common Weakness Enumeration) information for vulnerability classification',
    parameters: {
      type: 'OBJECT',
      properties: {
        cweId: {
          type: 'STRING',
          description: 'CWE ID (e.g., "CWE-89") or vulnerability type name',
        },
      },
      required: ['cweId'],
    },
  },
  {
    name: 'analyze_code_section',
    description: 'Deeply analyze a specific section of code for security issues',
    parameters: {
      type: 'OBJECT',
      properties: {
        code: {
          type: 'STRING',
          description: 'The code section to analyze',
        },
        startLine: {
          type: 'NUMBER',
          description: 'Starting line number',
        },
        endLine: {
          type: 'NUMBER',
          description: 'Ending line number',
        },
        context: {
          type: 'STRING',
          description: 'Additional context about what to look for',
        },
      },
      required: ['code'],
    },
  },
  {
    name: 'report_vulnerability',
    description: 'Report a found vulnerability with full details. Call this for EACH vulnerability discovered.',
    parameters: {
      type: 'OBJECT',
      properties: {
        type: {
          type: 'STRING',
          description: 'Vulnerability type (e.g., SQL Injection, XSS, Command Injection)',
        },
        severity: {
          type: 'STRING',
          description: 'Severity level: Critical, High, Medium, or Low',
        },
        lineNumbers: {
          type: 'ARRAY',
          items: { type: 'NUMBER' },
          description: 'Line numbers where the vulnerability exists',
        },
        codeSnippet: {
          type: 'STRING',
          description: 'The vulnerable code snippet',
        },
        description: {
          type: 'STRING',
          description: 'Detailed description of the vulnerability',
        },
        impact: {
          type: 'STRING',
          description: 'Potential impact if exploited',
        },
        owaspCategory: {
          type: 'STRING',
          description: 'OWASP Top 10 2021 category (e.g., A03:2021)',
        },
        cweId: {
          type: 'STRING',
          description: 'CWE identifier (e.g., CWE-89)',
        },
        confidence: {
          type: 'STRING',
          description: 'Confidence level: High, Medium, or Low',
        },
      },
      required: ['type', 'severity', 'lineNumbers', 'description', 'impact'],
    },
  },
  {
    name: 'submit_full_analysis',
    description: 'Submit a complete security analysis report including all vulnerabilities, attack vectors, risk areas, and recommendations in one call. Use this to efficiently report everything at once.',
    parameters: {
      type: 'OBJECT',
      properties: {
        vulnerabilities: {
          type: 'ARRAY',
          description: 'Array of all vulnerabilities found',
          items: {
            type: 'OBJECT',
            properties: {
              type: { type: 'STRING', description: 'Vulnerability type' },
              severity: { type: 'STRING', description: 'Critical, High, Medium, or Low' },
              lineNumbers: { type: 'ARRAY', items: { type: 'NUMBER' } },
              codeSnippet: { type: 'STRING' },
              description: { type: 'STRING' },
              impact: { type: 'STRING' },
              owaspCategory: { type: 'STRING' },
              cweId: { type: 'STRING' },
              confidence: { type: 'STRING' },
            },
          },
        },
        attackVectors: {
          type: 'ARRAY',
          description: 'Array of potential attack vectors',
          items: {
            type: 'OBJECT',
            properties: {
              vector: { type: 'STRING', description: 'Attack name' },
              description: { type: 'STRING', description: 'How the attack works' },
              likelihood: { type: 'STRING', description: 'High, Medium, or Low' },
            },
          },
        },
        riskAreas: {
          type: 'ARRAY',
          description: 'Array of risk areas in the code',
          items: {
            type: 'OBJECT',
            properties: {
              location: { type: 'STRING', description: 'Code location' },
              risk: { type: 'STRING', description: 'Risk description' },
              priority: { type: 'STRING', description: 'Critical, High, Medium, or Low' },
            },
          },
        },
        recommendations: {
          type: 'ARRAY',
          description: 'Array of security recommendations',
          items: {
            type: 'OBJECT',
            properties: {
              recommendation: { type: 'STRING' },
              priority: { type: 'STRING', description: 'Critical, High, Medium, or Low' },
              effort: { type: 'STRING', description: 'Low, Medium, or High' },
            },
          },
        },
        securePatterns: {
          type: 'ARRAY',
          description: 'Array of secure patterns found (positive findings)',
          items: { type: 'STRING' },
        },
        overallAssessment: {
          type: 'STRING',
          description: 'Overall security assessment summary',
        },
        securityScore: {
          type: 'NUMBER',
          description: 'Security score from 0-100',
        },
      },
      required: ['vulnerabilities', 'overallAssessment'],
    },
  },
  {
    name: 'generate_fix',
    description: 'Generate a secure fix for a specific vulnerability',
    parameters: {
      type: 'OBJECT',
      properties: {
        vulnerableCode: {
          type: 'STRING',
          description: 'The original vulnerable code',
        },
        vulnerabilityType: {
          type: 'STRING',
          description: 'Type of vulnerability to fix',
        },
        language: {
          type: 'STRING',
          description: 'Programming language',
        },
        context: {
          type: 'STRING',
          description: 'Additional context about the fix requirements',
        },
      },
      required: ['vulnerableCode', 'vulnerabilityType', 'language'],
    },
  },
  {
    name: 'apply_security_fix',
    description: 'Apply a security fix to the code. Returns the fixed code.',
    parameters: {
      type: 'OBJECT',
      properties: {
        originalCode: {
          type: 'STRING',
          description: 'The original complete code',
        },
        vulnerableSection: {
          type: 'STRING',
          description: 'The vulnerable code section to replace',
        },
        fixedSection: {
          type: 'STRING',
          description: 'The secure replacement code',
        },
        explanation: {
          type: 'STRING',
          description: 'Explanation of the security fix',
        },
      },
      required: ['originalCode', 'vulnerableSection', 'fixedSection', 'explanation'],
    },
  },
  {
    name: 'calculate_security_score',
    description: 'Calculate an overall security score based on found vulnerabilities',
    parameters: {
      type: 'OBJECT',
      properties: {
        totalVulnerabilities: {
          type: 'NUMBER',
          description: 'Total number of vulnerabilities found',
        },
        criticalCount: {
          type: 'NUMBER',
          description: 'Number of critical vulnerabilities',
        },
        highCount: {
          type: 'NUMBER',
          description: 'Number of high severity vulnerabilities',
        },
        mediumCount: {
          type: 'NUMBER',
          description: 'Number of medium severity vulnerabilities',
        },
        lowCount: {
          type: 'NUMBER',
          description: 'Number of low severity vulnerabilities',
        },
        codeLength: {
          type: 'NUMBER',
          description: 'Total lines of code analyzed',
        },
      },
      required: ['totalVulnerabilities', 'codeLength'],
    },
  },
  {
    name: 'report_attack_vector',
    description: 'Report a potential attack vector that could exploit vulnerabilities in the code',
    parameters: {
      type: 'OBJECT',
      properties: {
        vector: {
          type: 'STRING',
          description: 'Name of the attack vector (e.g., "SQL Injection Attack", "Remote Code Execution")',
        },
        description: {
          type: 'STRING',
          description: 'Detailed description of how the attack could be executed',
        },
        likelihood: {
          type: 'STRING',
          description: 'Likelihood of the attack: High, Medium, or Low',
        },
        affectedVulnerabilities: {
          type: 'ARRAY',
          items: { type: 'STRING' },
          description: 'List of vulnerability types that enable this attack',
        },
      },
      required: ['vector', 'description', 'likelihood'],
    },
  },
  {
    name: 'report_risk_area',
    description: 'Report a risk area in the code that needs security attention',
    parameters: {
      type: 'OBJECT',
      properties: {
        location: {
          type: 'STRING',
          description: 'Location in code (e.g., "Database Connection", "User Input Handler")',
        },
        risk: {
          type: 'STRING',
          description: 'Description of the security risk',
        },
        priority: {
          type: 'STRING',
          description: 'Priority level: Critical, High, Medium, or Low',
        },
      },
      required: ['location', 'risk', 'priority'],
    },
  },
  {
    name: 'add_recommendation',
    description: 'Add a security recommendation for improving the code',
    parameters: {
      type: 'OBJECT',
      properties: {
        recommendation: {
          type: 'STRING',
          description: 'The security recommendation',
        },
        priority: {
          type: 'STRING',
          description: 'Priority: Critical, High, Medium, or Low',
        },
        effort: {
          type: 'STRING',
          description: 'Implementation effort: Low, Medium, or High',
        },
      },
      required: ['recommendation', 'priority', 'effort'],
    },
  },
  {
    name: 'report_secure_pattern',
    description: 'Report a secure coding pattern found in the code (positive findings)',
    parameters: {
      type: 'OBJECT',
      properties: {
        pattern: {
          type: 'STRING',
          description: 'Description of the secure pattern found',
        },
      },
      required: ['pattern'],
    },
  },
  {
    name: 'finalize_scan',
    description: 'Finalize the vulnerability scan and return the complete results. Call this when done scanning.',
    parameters: {
      type: 'OBJECT',
      properties: {
        summary: {
          type: 'STRING',
          description: 'Summary of the security analysis',
        },
        recommendations: {
          type: 'ARRAY',
          items: { type: 'STRING' },
          description: 'List of security recommendations',
        },
      },
      required: ['summary'],
    },
  },
  {
    name: 'finalize_refactor',
    description: 'Finalize the refactoring process and return the complete fixed code. Call this when done refactoring.',
    parameters: {
      type: 'OBJECT',
      properties: {
        fixedCode: {
          type: 'STRING',
          description: 'The complete refactored code with all fixes applied',
        },
        changesSummary: {
          type: 'STRING',
          description: 'Summary of all changes made',
        },
        testingRecommendations: {
          type: 'ARRAY',
          items: { type: 'STRING' },
          description: 'Recommendations for testing the fixed code',
        },
      },
      required: ['fixedCode'],
    },
  },
];

class SecureRefactorAgent {
  constructor() {
    this.genAI = new GoogleGenerativeAI(config.gemini.apiKey);

    // Create function declarations for Gemini
    this.functionDeclarations = AGENT_TOOLS.map(tool => ({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
    }));

    // Initialize the model with function calling capabilities
    this.model = this.genAI.getGenerativeModel({
      model: config.gemini.model,
      generationConfig: {
        temperature: config.gemini.temperature,
        maxOutputTokens: config.gemini.maxTokens,
      },
      tools: [{ functionDeclarations: this.functionDeclarations }],
    });

    // State for the current agent session
    this.sessionState = {
      foundVulnerabilities: [],
      appliedFixes: [],
      currentCode: '',
      language: '',
      scanComplete: false,
      refactorComplete: false,
    };
  }

  /**
   * Reset session state for a new operation
   */
  resetSession() {
    this.sessionState = {
      foundVulnerabilities: [],
      appliedFixes: [],
      currentCode: '',
      language: '',
      scanComplete: false,
      refactorComplete: false,
    };
  }

  /**
   * Execute a tool function based on the agent's request
   */
  async executeTool(functionName, args) {
    logger.info(`Agent calling tool: ${functionName}`);
    logger.debug('Tool arguments:', JSON.stringify(args, null, 2));

    switch (functionName) {
      case 'detect_language':
        return this.toolDetectLanguage(args.code, args.filename);

      case 'static_pattern_scan':
        return this.toolStaticPatternScan(args.code, args.language);

      case 'lookup_owasp':
        return this.toolLookupOwasp(args.category);

      case 'lookup_cwe':
        return this.toolLookupCwe(args.cweId);

      case 'analyze_code_section':
        return this.toolAnalyzeCodeSection(args.code, args.startLine, args.endLine, args.context);

      case 'report_vulnerability':
        return this.toolReportVulnerability(args);

      case 'submit_full_analysis':
        return this.toolSubmitFullAnalysis(args);

      case 'generate_fix':
        return this.toolGenerateFix(args.vulnerableCode, args.vulnerabilityType, args.language, args.context);

      case 'apply_security_fix':
        return this.toolApplySecurityFix(args.originalCode, args.vulnerableSection, args.fixedSection, args.explanation);

      case 'calculate_security_score':
        return this.toolCalculateSecurityScore(args);

      case 'report_attack_vector':
        return this.toolReportAttackVector(args);

      case 'report_risk_area':
        return this.toolReportRiskArea(args);

      case 'add_recommendation':
        return this.toolAddRecommendation(args);

      case 'report_secure_pattern':
        return this.toolReportSecurePattern(args);

      case 'finalize_scan':
        return this.toolFinalizeScan(args.summary, args.recommendations);

      case 'finalize_refactor':
        return this.toolFinalizeRefactor(args.fixedCode, args.changesSummary, args.testingRecommendations);

      default:
        logger.warn(`Unknown tool called: ${functionName}`);
        return { error: `Unknown tool: ${functionName}` };
    }
  }

  // ==================== TOOL IMPLEMENTATIONS ====================

  toolDetectLanguage(code, filename = '') {
    const extensionMap = {
      '.js': 'javascript', '.jsx': 'javascript',
      '.ts': 'typescript', '.tsx': 'typescript',
      '.py': 'python', '.java': 'java',
      '.cs': 'csharp', '.php': 'php',
      '.go': 'go', '.rb': 'ruby',
    };

    // Check filename extension first
    for (const [ext, lang] of Object.entries(extensionMap)) {
      if (filename.toLowerCase().endsWith(ext)) {
        this.sessionState.language = lang;
        return { language: lang, detectedBy: 'file_extension' };
      }
    }

    // Heuristic detection from code patterns
    const codePatterns = {
      javascript: [/const\s+\w+\s*=/, /let\s+\w+\s*=/, /function\s+\w+\s*\(/, /=>\s*{/, /require\s*\(/],
      typescript: [/interface\s+\w+/, /:\s*(string|number|boolean)/, /type\s+\w+\s*=/, /<\w+>/],
      python: [/def\s+\w+\s*\(/, /import\s+\w+/, /from\s+\w+\s+import/, /:\s*$/, /self\./],
      java: [/public\s+class/, /private\s+\w+/, /public\s+static\s+void\s+main/, /System\.out/],
      php: [/<\?php/, /\$\w+\s*=/, /function\s+\w+\s*\(.*\)\s*{/, /echo\s+/],
      go: [/func\s+\w+\s*\(/, /package\s+\w+/, /import\s+\(/, /fmt\./],
      ruby: [/def\s+\w+/, /end$/, /puts\s+/, /require\s+['"]/, /@\w+\s*=/],
      csharp: [/using\s+System/, /namespace\s+\w+/, /public\s+class/, /Console\./],
    };

    for (const [lang, patterns] of Object.entries(codePatterns)) {
      const matches = patterns.filter(pattern => pattern.test(code)).length;
      if (matches >= 2) {
        this.sessionState.language = lang;
        return { language: lang, detectedBy: 'code_patterns', confidence: matches >= 3 ? 'high' : 'medium' };
      }
    }

    this.sessionState.language = 'javascript';
    return { language: 'javascript', detectedBy: 'default', confidence: 'low' };
  }

  toolStaticPatternScan(code, language) {
    const patterns = VULNERABILITY_PATTERNS[language] || VULNERABILITY_PATTERNS.javascript;
    const findings = [];

    for (const [vulnType, vulnPatterns] of Object.entries(patterns)) {
      const lines = code.split('\n');
      lines.forEach((line, index) => {
        for (const pattern of vulnPatterns) {
          pattern.lastIndex = 0; // Reset stateful lastIndex for /g regexes
          if (pattern.test(line)) {
            findings.push({
              type: vulnType,
              lineNumber: index + 1,
              lineContent: line.trim(),
              pattern: pattern.toString(),
              confidence: 'Medium',
              source: 'static_analysis',
            });
          }
        }
      });
    }

    return {
      totalFindings: findings.length,
      findings: findings,
      message: findings.length > 0
        ? `Found ${findings.length} potential issues via static analysis. Investigate each one.`
        : 'No obvious patterns found. Perform deeper analysis.',
    };
  }

  toolLookupOwasp(category) {
    if (category.toLowerCase() === 'all') {
      return {
        categories: Object.entries(OWASP_TOP_10_2021).map(([id, data]) => ({
          id,
          name: data.name,
          description: data.description,
        })),
      };
    }

    const data = OWASP_TOP_10_2021[category.toUpperCase()];
    if (data) {
      return {
        id: category,
        name: data.name,
        description: data.description,
        relatedCWEs: data.cwes,
        mitigations: data.mitigations,
      };
    }

    return { error: `OWASP category ${category} not found` };
  }

  toolLookupCwe(cweId) {
    // Direct lookup
    const normalized = cweId.toUpperCase().startsWith('CWE-') ? cweId.toUpperCase() : `CWE-${cweId}`;
    const data = CWE_DATABASE[normalized];

    if (data) {
      return {
        id: normalized,
        name: data.name,
        description: data.description,
        severity: data.severity,
        patterns: data.patterns,
      };
    }

    // Search by name
    for (const [id, cweData] of Object.entries(CWE_DATABASE)) {
      if (cweData.name.toLowerCase().includes(cweId.toLowerCase())) {
        return {
          id,
          name: cweData.name,
          description: cweData.description,
          severity: cweData.severity,
          patterns: cweData.patterns,
        };
      }
    }

    return {
      error: `CWE ${cweId} not found in local database`,
      suggestion: 'Use common CWE IDs like CWE-89 (SQL Injection), CWE-79 (XSS), CWE-78 (Command Injection)',
    };
  }

  toolAnalyzeCodeSection(code, startLine, endLine, context) {
    const lines = code.split('\n');
    const section = startLine && endLine
      ? lines.slice(startLine - 1, endLine).join('\n')
      : code;

    return {
      codeSection: section,
      lineCount: section.split('\n').length,
      context: context || 'General security analysis',
      hint: 'Look for: input validation, output encoding, authentication, authorization, cryptography, error handling',
    };
  }

  toolReportVulnerability(vulnData) {
    const vulnerability = {
      type: vulnData.type,
      severity: vulnData.severity,
      lineNumbers: vulnData.lineNumbers || [],
      codeSnippet: vulnData.codeSnippet || '',
      description: vulnData.description,
      impact: vulnData.impact,
      owaspCategory: vulnData.owaspCategory || 'Unknown',
      cweId: vulnData.cweId || 'Unknown',
      confidence: vulnData.confidence || 'Medium',
      reportedAt: new Date().toISOString(),
    };

    // Enrich with OWASP/CWE data
    if (vulnData.owaspCategory && OWASP_TOP_10_2021[vulnData.owaspCategory]) {
      vulnerability.owaspInfo = OWASP_TOP_10_2021[vulnData.owaspCategory];
    }
    if (vulnData.cweId && CWE_DATABASE[vulnData.cweId]) {
      vulnerability.cweInfo = CWE_DATABASE[vulnData.cweId];
    }

    this.sessionState.foundVulnerabilities.push(vulnerability);

    logger.info(`Vulnerability reported: ${vulnData.type} (${vulnData.severity})`);

    return {
      success: true,
      message: `Vulnerability "${vulnData.type}" recorded`,
      totalVulnerabilities: this.sessionState.foundVulnerabilities.length,
    };
  }

  toolSubmitFullAnalysis(args) {
    // Initialize analysisData if needed
    if (!this.sessionState.analysisData) {
      this.sessionState.analysisData = {
        recommendations: [],
        attackVectors: [],
        riskAreas: [],
        securePatterns: [],
        overallAssessment: '',
      };
    }

    // Process vulnerabilities
    if (args.vulnerabilities && Array.isArray(args.vulnerabilities)) {
      for (const vuln of args.vulnerabilities) {
        const vulnerability = {
          type: vuln.type,
          severity: vuln.severity,
          lineNumbers: vuln.lineNumbers || [],
          codeSnippet: vuln.codeSnippet || '',
          description: vuln.description,
          impact: vuln.impact,
          owaspCategory: vuln.owaspCategory || 'Unknown',
          cweId: vuln.cweId || 'Unknown',
          confidence: vuln.confidence || 'High',
          reportedAt: new Date().toISOString(),
        };

        // Enrich with OWASP/CWE data
        if (vuln.owaspCategory && OWASP_TOP_10_2021[vuln.owaspCategory]) {
          vulnerability.owaspInfo = OWASP_TOP_10_2021[vuln.owaspCategory];
        }
        if (vuln.cweId && CWE_DATABASE[vuln.cweId]) {
          vulnerability.cweInfo = CWE_DATABASE[vuln.cweId];
        }

        this.sessionState.foundVulnerabilities.push(vulnerability);
      }
      logger.info(`Batch reported ${args.vulnerabilities.length} vulnerabilities`);
    }

    // Process attack vectors
    if (args.attackVectors && Array.isArray(args.attackVectors)) {
      this.sessionState.analysisData.attackVectors = args.attackVectors.map(av => ({
        vector: av.vector,
        description: av.description,
        likelihood: av.likelihood || 'Medium',
        reportedAt: new Date().toISOString(),
      }));
      logger.info(`Reported ${args.attackVectors.length} attack vectors`);
    }

    // Process risk areas
    if (args.riskAreas && Array.isArray(args.riskAreas)) {
      this.sessionState.analysisData.riskAreas = args.riskAreas.map(ra => ({
        location: ra.location,
        risk: ra.risk,
        priority: ra.priority || 'Medium',
        reportedAt: new Date().toISOString(),
      }));
      logger.info(`Reported ${args.riskAreas.length} risk areas`);
    }

    // Process recommendations
    if (args.recommendations && Array.isArray(args.recommendations)) {
      this.sessionState.analysisData.recommendations = args.recommendations.map(rec => ({
        recommendation: rec.recommendation,
        priority: rec.priority || 'Medium',
        effort: rec.effort || 'Medium',
        addedAt: new Date().toISOString(),
      }));
      logger.info(`Reported ${args.recommendations.length} recommendations`);
    }

    // Process secure patterns
    if (args.securePatterns && Array.isArray(args.securePatterns)) {
      this.sessionState.analysisData.securePatterns = args.securePatterns;
    }

    // Store overall assessment
    if (args.overallAssessment) {
      this.sessionState.analysisData.overallAssessment = args.overallAssessment;
    }

    // Store or calculate security score
    if (args.securityScore !== undefined) {
      this.sessionState.analysisData.securityScore = args.securityScore;
    }

    this.sessionState.scanComplete = true;

    return {
      success: true,
      message: 'Full analysis submitted successfully',
      summary: {
        vulnerabilities: this.sessionState.foundVulnerabilities.length,
        attackVectors: this.sessionState.analysisData.attackVectors.length,
        riskAreas: this.sessionState.analysisData.riskAreas.length,
        recommendations: this.sessionState.analysisData.recommendations.length,
        securePatterns: this.sessionState.analysisData.securePatterns.length,
      },
    };
  }

  toolGenerateFix(vulnerableCode, vulnerabilityType, language, context) {
    // Return guidance for fixing - the actual fix will be generated by the AI
    const fixGuidance = {
      'SQL Injection': {
        approach: 'Use parameterized queries or prepared statements',
        example: language === 'javascript'
          ? 'db.query("SELECT * FROM users WHERE id = ?", [userId])'
          : 'Use parameterized queries with placeholders',
      },
      'XSS': {
        approach: 'Escape output or use template engines with auto-escaping',
        example: 'Use textContent instead of innerHTML, or escape HTML entities',
      },
      'Command Injection': {
        approach: 'Avoid shell commands, use safe APIs, validate input strictly',
        example: 'Use spawn with arguments array instead of exec with string concatenation',
      },
      'Path Traversal': {
        approach: 'Validate and sanitize file paths, use path.basename()',
        example: 'const safePath = path.join(baseDir, path.basename(userInput))',
      },
      'Hardcoded Credentials': {
        approach: 'Use environment variables or secure secret management',
        example: 'const password = process.env.DB_PASSWORD',
      },
    };

    const guidance = fixGuidance[vulnerabilityType] || {
      approach: 'Apply defense in depth: validate input, encode output, use secure APIs',
      example: 'Follow OWASP guidelines for the specific vulnerability type',
    };

    return {
      vulnerabilityType,
      language,
      guidance,
      context: context || 'Apply secure coding practices',
    };
  }

  toolApplySecurityFix(originalCode, vulnerableSection, fixedSection, explanation) {
    const fixedCode = originalCode.replaceAll(vulnerableSection, fixedSection);

    this.sessionState.appliedFixes.push({
      original: vulnerableSection,
      fixed: fixedSection,
      explanation,
      appliedAt: new Date().toISOString(),
    });

    this.sessionState.currentCode = fixedCode;

    return {
      success: true,
      codeUpdated: true,
      fixesApplied: this.sessionState.appliedFixes.length,
      explanation,
    };
  }

  toolCalculateSecurityScore(args) {
    const { totalVulnerabilities = 0, criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0, codeLength: _codeLength = 100 } = args;

    const weights = { Critical: 25, High: 15, Medium: 8, Low: 3 };
    const deductions = (criticalCount * weights.Critical) +
                     (highCount * weights.High) +
                     (mediumCount * weights.Medium) +
                     (lowCount * weights.Low);

    // Base score of 100, reduced by vulnerability severity
    const score = Math.max(0, Math.min(100, 100 - deductions));

    let riskLevel;
    if (score >= 90) riskLevel = 'Low';
    else if (score >= 70) riskLevel = 'Medium';
    else if (score >= 50) riskLevel = 'High';
    else riskLevel = 'Critical';

    return {
      score,
      riskLevel,
      totalVulnerabilities,
      breakdown: {
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
      },
    };
  }

  toolReportAttackVector(args) {
    const attackVector = {
      vector: args.vector,
      description: args.description,
      likelihood: args.likelihood || 'Medium',
      affectedVulnerabilities: args.affectedVulnerabilities || [],
      reportedAt: new Date().toISOString(),
    };

    // Initialize analysisData if needed
    if (!this.sessionState.analysisData) {
      this.sessionState.analysisData = {
        recommendations: [],
        attackVectors: [],
        riskAreas: [],
        securePatterns: [],
        overallAssessment: '',
      };
    }

    this.sessionState.analysisData.attackVectors.push(attackVector);
    logger.info(`Attack vector reported: ${args.vector} (${args.likelihood})`);

    return {
      success: true,
      message: `Attack vector "${args.vector}" recorded`,
      totalAttackVectors: this.sessionState.analysisData.attackVectors.length,
    };
  }

  toolReportRiskArea(args) {
    const riskArea = {
      location: args.location,
      risk: args.risk,
      priority: args.priority || 'Medium',
      reportedAt: new Date().toISOString(),
    };

    // Initialize analysisData if needed
    if (!this.sessionState.analysisData) {
      this.sessionState.analysisData = {
        recommendations: [],
        attackVectors: [],
        riskAreas: [],
        securePatterns: [],
        overallAssessment: '',
      };
    }

    this.sessionState.analysisData.riskAreas.push(riskArea);
    logger.info(`Risk area reported: ${args.location} (${args.priority})`);

    return {
      success: true,
      message: `Risk area "${args.location}" recorded`,
      totalRiskAreas: this.sessionState.analysisData.riskAreas.length,
    };
  }

  toolAddRecommendation(args) {
    const recommendation = {
      recommendation: args.recommendation,
      priority: args.priority || 'Medium',
      effort: args.effort || 'Medium',
      addedAt: new Date().toISOString(),
    };

    // Initialize analysisData if needed
    if (!this.sessionState.analysisData) {
      this.sessionState.analysisData = {
        recommendations: [],
        attackVectors: [],
        riskAreas: [],
        securePatterns: [],
        overallAssessment: '',
      };
    }

    this.sessionState.analysisData.recommendations.push(recommendation);
    logger.info(`Recommendation added: ${args.recommendation.substring(0, 50)}...`);

    return {
      success: true,
      message: 'Recommendation recorded',
      totalRecommendations: this.sessionState.analysisData.recommendations.length,
    };
  }

  toolReportSecurePattern(args) {
    // Initialize analysisData if needed
    if (!this.sessionState.analysisData) {
      this.sessionState.analysisData = {
        recommendations: [],
        attackVectors: [],
        riskAreas: [],
        securePatterns: [],
        overallAssessment: '',
      };
    }

    this.sessionState.analysisData.securePatterns.push(args.pattern);
    logger.info(`Secure pattern found: ${args.pattern.substring(0, 50)}...`);

    return {
      success: true,
      message: 'Secure pattern recorded',
      totalSecurePatterns: this.sessionState.analysisData.securePatterns.length,
    };
  }

  toolFinalizeScan(summary, recommendations = []) {
    this.sessionState.scanComplete = true;

    // Store overall assessment if provided
    if (this.sessionState.analysisData) {
      this.sessionState.analysisData.overallAssessment = summary;
    }

    const severityCounts = {
      Critical: 0, High: 0, Medium: 0, Low: 0,
    };

    for (const vuln of this.sessionState.foundVulnerabilities) {
      severityCounts[vuln.severity] = (severityCounts[vuln.severity] || 0) + 1;
    }

    return {
      scanComplete: true,
      summary,
      recommendations,
      totalVulnerabilities: this.sessionState.foundVulnerabilities.length,
      severityBreakdown: severityCounts,
      riskLevel: severityCounts.Critical > 0 ? 'Critical'
        : severityCounts.High > 0 ? 'High'
          : severityCounts.Medium > 0 ? 'Medium'
            : severityCounts.Low > 0 ? 'Low' : 'None',
    };
  }
  toolFinalizeRefactor(fixedCode, changesSummary, testingRecommendations = []) {
    this.sessionState.refactorComplete = true;
    if (fixedCode) {
      this.sessionState.currentCode = fixedCode;
    }

    return {
      refactorComplete: true,
      fixedCode: fixedCode || this.sessionState.currentCode,
      changesSummary: changesSummary || 'Security vulnerabilities have been fixed',
      testingRecommendations,
      totalFixes: this.sessionState.appliedFixes.length,
    };
  }

  // ==================== MAIN AGENT METHODS ====================

  /**
   * Run the agent loop - processes function calls until completion
   */
  async runAgentLoop(chat, initialPrompt, maxIterations = 20) {
    let response = await chat.sendMessage(initialPrompt);
    let iterations = 0;

    while (iterations < maxIterations) {
      iterations++;
      const candidate = response.response.candidates?.[0];

      if (!candidate) {
        logger.error('No response candidate from model');
        break;
      }

      const parts = candidate.content?.parts || [];
      const functionCalls = parts.filter(part => part.functionCall);

      if (functionCalls.length === 0) {
        // No more function calls - agent is done
        logger.info(`Agent completed after ${iterations} iterations`);
        break;
      }

      // Execute all function calls and collect results
      const functionResponses = [];

      for (const part of functionCalls) {
        const { name, args } = part.functionCall;

        try {
          const result = await this.executeTool(name, args);
          functionResponses.push({
            functionResponse: {
              name: name,
              response: result,
            },
          });
        } catch (error) {
          logger.error(`Tool execution error for ${name}:`, error);
          functionResponses.push({
            functionResponse: {
              name: name,
              response: { error: error.message },
            },
          });
        }
      }

      // Send function responses back to the model
      response = await chat.sendMessage(functionResponses);
    }

    if (iterations >= maxIterations) {
      logger.warn(`Agent reached max iterations (${maxIterations})`);
    }

    return response;
  }

  /**
   * Scan code for vulnerabilities using the AI Agent
   */
  async scanVulnerabilities(code, language = null, filename = '') {
    this.resetSession();
    this.sessionState.currentCode = code;
    // Initialize analysis data for the scan as well
    this.sessionState.analysisData = {
      recommendations: [],
      attackVectors: [],
      riskAreas: [],
      securePatterns: [],
      overallAssessment: '',
      securityScore: null,
    };

    logger.info('Starting AI Agent vulnerability scan');

    const instructions = getAgentInstructions('scan', { code, language, filename });

    try {
      // Start a chat session with the agent
      const chat = this.model.startChat({
        history: [],
        generationConfig: {
          temperature: config.gemini.temperature,
          maxOutputTokens: config.gemini.maxTokens,
        },
      });

      // Run the agent loop
      await this.runAgentLoop(chat, instructions);

      // Calculate score if not provided by agent
      const vulns = this.sessionState.foundVulnerabilities;
      const criticalCount = vulns.filter(v => v.severity === 'Critical').length;
      const highCount = vulns.filter(v => v.severity === 'High').length;
      const mediumCount = vulns.filter(v => v.severity === 'Medium').length;
      const lowCount = vulns.filter(v => v.severity === 'Low').length;

      let score, riskLevel;
      if (this.sessionState.analysisData.securityScore !== null) {
        score = this.sessionState.analysisData.securityScore;
        riskLevel = score >= 90 ? 'Low' : score >= 70 ? 'Medium' : score >= 50 ? 'High' : 'Critical';
      } else {
        const scoreResult = this.toolCalculateSecurityScore({
          totalVulnerabilities: vulns.length,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          codeLength: code.split('\n').length,
        });
        score = scoreResult.score;
        riskLevel = scoreResult.riskLevel;
      }

      // Return the accumulated results including analysis data
      return {
        success: true,
        language: this.sessionState.language || language || 'unknown',
        vulnerabilities: this.sessionState.foundVulnerabilities,
        summary: this.generateSummary(this.sessionState.foundVulnerabilities),
        analysis: {
          securityScore: score,
          riskLevel: riskLevel,
          breakdown: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
          recommendations: this.sessionState.analysisData.recommendations,
          attackVectors: this.sessionState.analysisData.attackVectors,
          riskAreas: this.sessionState.analysisData.riskAreas,
          securePatterns: this.sessionState.analysisData.securePatterns,
          overallAssessment: this.sessionState.analysisData.overallAssessment || this.generateOverallAssessment({ score }),
        },
        agentIterations: true,
      };

    } catch (error) {
      logger.error('Error during AI Agent scan:', error);
      return {
        success: false,
        error: error.message,
        language: this.sessionState.language || language || 'unknown',
        vulnerabilities: this.sessionState.foundVulnerabilities,
      };
    }
  }

  /**
   * Refactor code to fix a specific vulnerability
   */
  async refactorVulnerability(code, vulnerability, language = null) {
    this.resetSession();
    this.sessionState.currentCode = code;
    this.sessionState.language = language || 'javascript';

    logger.info(`Starting AI Agent refactor for: ${vulnerability.type}`);

    const instructions = getAgentInstructions('refactor', { code, vulnerability, language });

    try {
      const chat = this.model.startChat({
        history: [],
        generationConfig: {
          temperature: config.gemini.temperature,
          maxOutputTokens: config.gemini.maxTokens,
        },
      });

      await this.runAgentLoop(chat, instructions);

      // Transform appliedFixes to match frontend expectations
      const fixesSummary = this.sessionState.appliedFixes.map(fix => ({
        vulnerabilityType: vulnerability.type,
        type: vulnerability.type,
        fixApplied: fix.explanation,
        explanation: fix.explanation,
        original: fix.original,
        fixed: fix.fixed,
      }));

      const changes = this.sessionState.appliedFixes.map(fix => ({
        explanation: fix.explanation,
        original: fix.original,
        fixed: fix.fixed,
      }));

      return {
        success: true,
        originalCode: code,
        refactoredCode: this.sessionState.currentCode,
        fixedCode: this.sessionState.currentCode,
        fixesSummary: fixesSummary,
        changes: changes,
        securityImprovements: fixesSummary.map(f => `Fixed: ${f.explanation}`),
        vulnerability: vulnerability,
      };

    } catch (error) {
      logger.error('Error during AI Agent refactor:', error);
      return {
        success: false,
        error: error.message,
        originalCode: code,
        vulnerability: vulnerability,
      };
    }
  }

  /**
   * Refactor all vulnerabilities at once
   */
  async refactorAllVulnerabilities(code, vulnerabilities, language = null) {
    this.resetSession();
    this.sessionState.currentCode = code;
    this.sessionState.language = language || 'javascript';
    // Store vulnerabilities for reference during refactoring
    this.sessionState.vulnerabilitiesToFix = vulnerabilities;

    logger.info(`Starting AI Agent batch refactor for ${vulnerabilities.length} vulnerabilities`);

    const instructions = getAgentInstructions('refactorAll', { code, vulnerabilities, language });

    try {
      const chat = this.model.startChat({
        history: [],
        generationConfig: {
          temperature: config.gemini.temperature,
          maxOutputTokens: config.gemini.maxTokens,
        },
      });

      await this.runAgentLoop(chat, instructions);

      // Transform appliedFixes to match frontend expectations
      const fixesSummary = this.sessionState.appliedFixes.map((fix, index) => ({
        vulnerabilityType: vulnerabilities[index]?.type || fix.vulnerabilityType || 'Unknown',
        type: vulnerabilities[index]?.type || fix.vulnerabilityType || 'Unknown',
        fixApplied: fix.explanation,
        explanation: fix.explanation,
        original: fix.original,
        fixed: fix.fixed,
      }));

      // Create changes array for the frontend
      const changes = this.sessionState.appliedFixes.map(fix => ({
        explanation: fix.explanation,
        original: fix.original,
        fixed: fix.fixed,
      }));

      // Generate security improvements list
      const securityImprovements = this.sessionState.appliedFixes.map(fix =>
        `Fixed: ${fix.explanation}`,
      );

      return {
        success: true,
        originalCode: code,
        fixedCode: this.sessionState.currentCode,
        fixesSummary: fixesSummary,
        changes: changes,
        securityImprovements: securityImprovements,
        remainingRisks: [],
        vulnerabilitiesFixed: this.sessionState.appliedFixes.length,
      };

    } catch (error) {
      logger.error('Error during AI Agent batch refactor:', error);
      return {
        success: false,
        error: error.message,
        originalCode: code,
      };
    }
  }

  /**
   * Analyze security posture of code
   */
  async analyzeSecurityPosture(code, language = null) {
    this.resetSession();
    this.sessionState.currentCode = code;
    // Initialize analysis data holders
    this.sessionState.analysisData = {
      recommendations: [],
      attackVectors: [],
      riskAreas: [],
      securePatterns: [],
      overallAssessment: '',
      securityScore: null,
    };

    logger.info('Starting AI Agent security posture analysis');

    const instructions = getAgentInstructions('analyze', { code, language });

    try {
      const chat = this.model.startChat({
        history: [],
        generationConfig: {
          temperature: config.gemini.temperature,
          maxOutputTokens: config.gemini.maxTokens,
        },
      });

      await this.runAgentLoop(chat, instructions);

      // Calculate severity counts from found vulnerabilities
      const vulns = this.sessionState.foundVulnerabilities;
      const criticalCount = vulns.filter(v => v.severity === 'Critical').length;
      const highCount = vulns.filter(v => v.severity === 'High').length;
      const mediumCount = vulns.filter(v => v.severity === 'Medium').length;
      const lowCount = vulns.filter(v => v.severity === 'Low').length;

      // Use submitted score if available, otherwise calculate
      let score, riskLevel;
      if (this.sessionState.analysisData.securityScore !== null) {
        score = this.sessionState.analysisData.securityScore;
        riskLevel = score >= 90 ? 'Low' : score >= 70 ? 'Medium' : score >= 50 ? 'High' : 'Critical';
      } else {
        const scoreResult = this.toolCalculateSecurityScore({
          totalVulnerabilities: vulns.length,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          codeLength: code.split('\n').length,
        });
        score = scoreResult.score;
        riskLevel = scoreResult.riskLevel;
      }

      return {
        success: true,
        language: this.sessionState.language || language || 'unknown',
        analysis: {
          securityScore: score,
          riskLevel: riskLevel,
          vulnerabilities: this.sessionState.foundVulnerabilities,
          breakdown: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
          recommendations: this.sessionState.analysisData.recommendations,
          attackVectors: this.sessionState.analysisData.attackVectors,
          riskAreas: this.sessionState.analysisData.riskAreas,
          securePatterns: this.sessionState.analysisData.securePatterns,
          overallAssessment: this.sessionState.analysisData.overallAssessment || this.generateOverallAssessment({ score }),
        },
      };

    } catch (error) {
      logger.error('Error during AI Agent analysis:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Generate overall assessment based on score
   */
  generateOverallAssessment(scoreResult) {
    if (scoreResult.score >= 90) {
      return 'The code has strong security practices with minimal vulnerabilities.';
    } else if (scoreResult.score >= 70) {
      return 'The code has moderate security with some areas requiring attention.';
    } else if (scoreResult.score >= 50) {
      return 'The code has significant security issues that should be addressed.';
    } else {
      return 'The code has critical security vulnerabilities requiring immediate attention.';
    }
  }

  /**
   * Generate summary of findings
   */
  generateSummary(findings) {
    const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const owaspCounts = {};
    const typeCounts = {};

    for (const finding of findings) {
      severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
      if (finding.owaspCategory) {
        owaspCounts[finding.owaspCategory] = (owaspCounts[finding.owaspCategory] || 0) + 1;
      }
      if (finding.type) {
        typeCounts[finding.type] = (typeCounts[finding.type] || 0) + 1;
      }
    }

    return {
      totalVulnerabilities: findings.length,
      severityBreakdown: severityCounts,
      owaspCategories: owaspCounts,
      vulnerabilityTypes: typeCounts,
      riskLevel: severityCounts.Critical > 0 ? 'Critical'
        : severityCounts.High > 0 ? 'High'
          : severityCounts.Medium > 0 ? 'Medium'
            : severityCounts.Low > 0 ? 'Low' : 'None',
    };
  }
}

export default SecureRefactorAgent;
