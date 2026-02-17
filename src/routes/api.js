/**
 * API Routes for the Secure Refactoring Agent
 */

import express from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import SecureRefactorAgent from '../agent/SecureRefactorAgent.js';
import logger from '../utils/logger.js';
import config from '../config/index.js';
import { OWASP_TOP_10_2021, CWE_DATABASE } from '../knowledge/vulnerabilities.js';
import { saveScan, getScan, listScans, scanCount, clearAllScans } from '../database/index.js';

const router = express.Router();
const agent = new SecureRefactorAgent();

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 1024 * 1024, // 1MB max
  },
  fileFilter: (req, file, cb) => {
    const allowedExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.php', '.go', '.rb', '.cs'];
    const ext = '.' + file.originalname.split('.').pop().toLowerCase();
    if (allowedExtensions.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Allowed: ' + allowedExtensions.join(', ')));
    }
  },
});

// Scan results are now persisted in SQLite (see src/database/index.js)

/**
 * Health check endpoint
 */
router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    agent: 'AI Secure Refactoring Agent with Function Calling',
    capabilities: [
      'vulnerability_scanning',
      'code_refactoring',
      'security_analysis',
      'function_calling_agent',
    ],
  });
});

/**
 * Get agent information
 * GET /api/agent/info
 */
router.get('/agent/info', (req, res) => {
  res.json({
    name: 'Secure Refactor Agent',
    version: '2.0.0',
    type: 'Function-Calling AI Agent',
    model: config.gemini.model,
    capabilities: {
      scan: 'Scan code for security vulnerabilities using AI with function calling',
      refactor: 'Fix individual vulnerabilities using intelligent code analysis',
      refactorAll: 'Fix all vulnerabilities in one pass',
      analyze: 'Comprehensive security posture analysis',
    },
    tools: [
      'detect_language',
      'static_pattern_scan',
      'lookup_owasp',
      'lookup_cwe',
      'analyze_code_section',
      'report_vulnerability',
      'generate_fix',
      'apply_security_fix',
      'calculate_security_score',
      'finalize_scan',
      'finalize_refactor',
    ],
    supportedStandards: ['OWASP Top 10 2021', 'CWE'],
  });
});

/**
 * Scan code for vulnerabilities
 * POST /api/scan
 * Body: { code: string, language?: string, filename?: string }
 */
router.post('/scan', async (req, res) => {
  try {
    const { code, language, filename } = req.body;

    if (!code) {
      return res.status(400).json({
        success: false,
        error: 'Code is required',
      });
    }

    if (code.length > config.agent.maxCodeLength) {
      return res.status(400).json({
        success: false,
        error: `Code exceeds maximum length of ${config.agent.maxCodeLength} characters`,
      });
    }

    const scanId = uuidv4();
    logger.info(`Starting scan ${scanId}`);

    const result = await agent.scanVulnerabilities(code, language, filename);

    // Persist result to SQLite
    saveScan(scanId, result, code, filename);

    res.json({
      ...result,
      scanId,
    });
  } catch (error) {
    logger.error('Scan error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * Scan uploaded file for vulnerabilities
 * POST /api/scan/file
 */
router.post('/scan/file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'File is required',
      });
    }

    const code = req.file.buffer.toString('utf-8');
    const filename = req.file.originalname;

    const scanId = uuidv4();
    logger.info(`Starting file scan ${scanId}: ${filename}`);

    const result = await agent.scanVulnerabilities(code, null, filename);

    // Persist result to SQLite
    saveScan(scanId, result, code, filename);

    res.json({
      ...result,
      scanId,
      filename,
    });
  } catch (error) {
    logger.error('File scan error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * Refactor a specific vulnerability
 * POST /api/refactor
 * Body: { code: string, vulnerability: object, language?: string }
 */
router.post('/refactor', async (req, res) => {
  try {
    const { code, vulnerability, language } = req.body;

    if (!code || !vulnerability) {
      return res.status(400).json({
        success: false,
        error: 'Code and vulnerability are required',
      });
    }

    logger.info(`Refactoring vulnerability: ${vulnerability.type}`);

    const result = await agent.refactorVulnerability(code, vulnerability, language);

    res.json(result);
  } catch (error) {
    logger.error('Refactor error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * Refactor all vulnerabilities from a previous scan
 * POST /api/refactor/all
 * Body: { scanId: string } OR { code: string, vulnerabilities: array }
 */
router.post('/refactor/all', async (req, res) => {
  try {
    let code, vulnerabilities, language;

    if (req.body.scanId) {
      // Retrieve from database
      const scan = getScan(req.body.scanId);
      if (!scan) {
        return res.status(404).json({
          success: false,
          error: 'Scan not found',
        });
      }
      code = scan.code;
      vulnerabilities = scan.vulnerabilities;
      language = scan.language;
    } else {
      // Use provided data
      code = req.body.code;
      vulnerabilities = req.body.vulnerabilities;
      language = req.body.language;
    }

    if (!code || !vulnerabilities || vulnerabilities.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Code and vulnerabilities are required',
      });
    }

    logger.info(`Refactoring ${vulnerabilities.length} vulnerabilities`);

    const result = await agent.refactorAllVulnerabilities(code, vulnerabilities, language);

    res.json(result);
  } catch (error) {
    logger.error('Batch refactor error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * Analyze security posture
 * POST /api/analyze
 * Body: { code: string, language?: string }
 */
router.post('/analyze', async (req, res) => {
  try {
    const { code, language } = req.body;

    if (!code) {
      return res.status(400).json({
        success: false,
        error: 'Code is required',
      });
    }

    logger.info('Starting security posture analysis');

    const result = await agent.analyzeSecurityPosture(code, language);

    res.json(result);
  } catch (error) {
    logger.error('Analysis error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * Get previous scan result
 * GET /api/scan/:scanId
 */
router.get('/scan/:scanId', (req, res) => {
  const scan = getScan(req.params.scanId);

  if (!scan) {
    return res.status(404).json({
      success: false,
      error: 'Scan not found',
    });
  }

  res.json(scan);
});

/**
 * List recent scans (metadata only)
 * GET /api/scans?limit=20
 */
router.get('/scans', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  const scans = listScans(limit);
  res.json({ scans, total: scanCount() });
});

/**
 * Clear all scan history
 * DELETE /api/scans
 */
router.delete('/scans', (req, res) => {
  const removed = clearAllScans();
  logger.info(`Cleared ${removed} scans from history`);
  res.json({ success: true, removed });
});

/**
 * Get supported languages
 * GET /api/languages
 */
router.get('/languages', (req, res) => {
  res.json({
    supported: config.agent.supportedLanguages,
    recommended: ['javascript', 'python', 'java', 'php'],
  });
});

/**
 * Get OWASP Top 10 reference
 * GET /api/reference/owasp
 */
router.get('/reference/owasp', (req, res) => {
  res.json(OWASP_TOP_10_2021);
});

/**
 * Get CWE reference
 * GET /api/reference/cwe
 */
router.get('/reference/cwe', (req, res) => {
  res.json(CWE_DATABASE);
});

export default router;
