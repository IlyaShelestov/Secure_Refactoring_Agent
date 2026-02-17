/**
 * Tests for the SQLite database persistence layer.
 * Uses a temporary in-memory database to avoid touching the production file.
 */

import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// Helper: spin up an isolated database with the same schema as production
// ---------------------------------------------------------------------------
function createTestDb() {
  const db = new Database(':memory:');
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      scan_id       TEXT PRIMARY KEY,
      timestamp     TEXT NOT NULL DEFAULT (datetime('now')),
      language      TEXT,
      filename      TEXT,
      code          TEXT NOT NULL,
      success       INTEGER NOT NULL DEFAULT 1,
      security_score INTEGER,
      risk_level    TEXT,
      summary       TEXT,
      raw_result    TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id       TEXT NOT NULL,
      type          TEXT,
      severity      TEXT,
      owasp         TEXT,
      cwe           TEXT,
      description   TEXT,
      location      TEXT,
      confidence    REAL,
      raw_json      TEXT NOT NULL,
      FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
    CREATE INDEX IF NOT EXISTS idx_scans_ts   ON scans(timestamp);
    CREATE INDEX IF NOT EXISTS idx_scans_lang ON scans(language);
  `);

  // Prepared statements mirroring src/database/index.js
  const stmts = {
    insertScan: db.prepare(`
      INSERT INTO scans (scan_id, timestamp, language, filename, code, success,
                         security_score, risk_level, summary, raw_result)
      VALUES (@scanId, @timestamp, @language, @filename, @code, @success,
              @securityScore, @riskLevel, @summary, @rawResult)
    `),
    insertVuln: db.prepare(`
      INSERT INTO vulnerabilities (scan_id, type, severity, owasp, cwe,
                                   description, location, confidence, raw_json)
      VALUES (@scanId, @type, @severity, @owasp, @cwe,
              @description, @location, @confidence, @rawJson)
    `),
    selectScan: db.prepare('SELECT * FROM scans WHERE scan_id = ?'),
    selectVulns: db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id'),
    selectRecent: db.prepare('SELECT scan_id, timestamp, language, filename, success, security_score, risk_level, summary FROM scans ORDER BY timestamp DESC LIMIT ?'),
    deleteScan: db.prepare('DELETE FROM scans WHERE scan_id = ?'),
    countScans: db.prepare('SELECT COUNT(*) as total FROM scans'),
  };

  return { db, stmts };
}

// Helpers that mirror the public API of src/database/index.js
function saveScan({ stmts, db }, scanId, result, code, filename) {
  const saveTransaction = db.transaction(() => {
    stmts.insertScan.run({
      scanId,
      timestamp: new Date().toISOString(),
      language: result.language || null,
      filename: filename || null,
      code,
      success: result.success ? 1 : 0,
      securityScore: result.securityScore ?? null,
      riskLevel: result.riskLevel ?? null,
      summary: result.summary || null,
      rawResult: JSON.stringify(result),
    });
    for (const v of (result.vulnerabilities || [])) {
      stmts.insertVuln.run({
        scanId,
        type: v.type || null,
        severity: v.severity || null,
        owasp: v.owasp || null,
        cwe: v.cwe || null,
        description: v.description || null,
        location: v.location || null,
        confidence: v.confidence ?? null,
        rawJson: JSON.stringify(v),
      });
    }
  });
  saveTransaction();
}

function getScan({ stmts }, scanId) {
  const row = stmts.selectScan.get(scanId);
  if (!row) return null;
  const result = JSON.parse(row.raw_result);
  return { ...result, scanId: row.scan_id, timestamp: row.timestamp, code: row.code, filename: row.filename };
}

function listScans({ stmts }, limit = 20) {
  return stmts.selectRecent.all(limit).map(r => ({
    scanId: r.scan_id, timestamp: r.timestamp, language: r.language,
    filename: r.filename, success: !!r.success, securityScore: r.security_score,
    riskLevel: r.risk_level, summary: r.summary,
  }));
}

function removeScan({ stmts }, scanId) {
  return stmts.deleteScan.run(scanId).changes > 0;
}

function scanCount({ stmts }) {
  return stmts.countScans.get().total;
}

function clearAllScans({ db }) {
  return db.prepare('DELETE FROM scans').run().changes;
}

// ===================== Database Tests =====================

describe('Database Schema', () => {
  let ctx;
  beforeEach(() => { ctx = createTestDb(); });
  afterEach(() => { ctx.db.close(); });

  test('schema creates scans table with expected columns', () => {
    const cols = ctx.db.pragma('table_info(scans)').map(c => c.name);
    expect(cols).toEqual(expect.arrayContaining([
      'scan_id', 'timestamp', 'language', 'filename', 'code',
      'success', 'security_score', 'risk_level', 'summary', 'raw_result',
    ]));
  });

  test('schema creates vulnerabilities table with expected columns', () => {
    const cols = ctx.db.pragma('table_info(vulnerabilities)').map(c => c.name);
    expect(cols).toEqual(expect.arrayContaining([
      'id', 'scan_id', 'type', 'severity', 'owasp', 'cwe',
      'description', 'location', 'confidence', 'raw_json',
    ]));
  });

  test('foreign key constraint is enforced', () => {
    expect(() => {
      ctx.stmts.insertVuln.run({
        scanId: 'non-existent', type: 'test', severity: 'low',
        owasp: null, cwe: null, description: null, location: null,
        confidence: null, rawJson: '{}',
      });
    }).toThrow();
  });
});

describe('Database CRUD — saveScan / getScan', () => {
  let ctx;
  beforeEach(() => { ctx = createTestDb(); });
  afterEach(() => { ctx.db.close(); });

  const sampleResult = {
    success: true,
    language: 'javascript',
    securityScore: 40,
    riskLevel: 'high',
    summary: 'Multiple issues found',
    vulnerabilities: [
      { type: 'SQL Injection', severity: 'critical', owasp: 'A03:2021', cwe: 'CWE-89', description: 'Concatenated query', location: 'Line 10', confidence: 0.95 },
      { type: 'XSS', severity: 'medium', owasp: 'A03:2021', cwe: 'CWE-79', description: 'Reflected input', location: 'Line 20', confidence: 0.85 },
    ],
  };

  test('saves and retrieves a scan with vulnerabilities', () => {
    saveScan(ctx, 'scan-001', sampleResult, 'const x = 1;', 'test.js');
    const scan = getScan(ctx, 'scan-001');

    expect(scan).not.toBeNull();
    expect(scan.scanId).toBe('scan-001');
    expect(scan.language).toBe('javascript');
    expect(scan.securityScore).toBe(40);
    expect(scan.vulnerabilities).toHaveLength(2);
    expect(scan.code).toBe('const x = 1;');
    expect(scan.filename).toBe('test.js');
  });

  test('returns null for non-existent scan', () => {
    expect(getScan(ctx, 'no-such-id')).toBeNull();
  });

  test('stores vulnerabilities correctly', () => {
    saveScan(ctx, 'scan-002', sampleResult, 'code', null);
    const vulns = ctx.stmts.selectVulns.all('scan-002');
    expect(vulns).toHaveLength(2);
    expect(vulns[0].type).toBe('SQL Injection');
    expect(vulns[0].severity).toBe('critical');
    expect(vulns[1].type).toBe('XSS');
  });

  test('handles scan with no vulnerabilities', () => {
    const clean = { success: true, language: 'python', securityScore: 100, riskLevel: 'low', summary: 'Clean', vulnerabilities: [] };
    saveScan(ctx, 'scan-clean', clean, 'print("hi")', 'clean.py');
    const scan = getScan(ctx, 'scan-clean');
    expect(scan.securityScore).toBe(100);
    expect(scan.vulnerabilities).toHaveLength(0);
  });
});

describe('Database — listScans / scanCount', () => {
  let ctx;
  beforeEach(() => { ctx = createTestDb(); });
  afterEach(() => { ctx.db.close(); });

  test('lists scans ordered by timestamp descending', () => {
    const r = { success: true, language: 'python', securityScore: 80, riskLevel: 'low', summary: 'ok', vulnerabilities: [] };
    saveScan(ctx, 'a', r, 'code1', null);
    saveScan(ctx, 'b', r, 'code2', null);
    saveScan(ctx, 'c', r, 'code3', null);

    const list = listScans(ctx, 2);
    expect(list).toHaveLength(2);
    expect(list[0].scanId).toBe('c');
    expect(list[1].scanId).toBe('b');
  });

  test('scanCount returns correct total', () => {
    expect(scanCount(ctx)).toBe(0);
    const r = { success: true, language: 'go', securityScore: 90, riskLevel: 'low', summary: '', vulnerabilities: [] };
    saveScan(ctx, 's1', r, 'code', null);
    saveScan(ctx, 's2', r, 'code', null);
    expect(scanCount(ctx)).toBe(2);
  });
});

describe('Database — removeScan', () => {
  let ctx;
  beforeEach(() => { ctx = createTestDb(); });
  afterEach(() => { ctx.db.close(); });

  test('deletes scan and cascades to vulnerabilities', () => {
    const r = { success: true, language: 'java', securityScore: 50, riskLevel: 'medium', summary: '', vulnerabilities: [{ type: 'SQLi', severity: 'high', owasp: '', cwe: '', description: '', location: '', confidence: 0.9 }] };
    saveScan(ctx, 'del-1', r, 'code', null);
    expect(scanCount(ctx)).toBe(1);

    const removed = removeScan(ctx, 'del-1');
    expect(removed).toBe(true);
    expect(scanCount(ctx)).toBe(0);
    expect(ctx.stmts.selectVulns.all('del-1')).toHaveLength(0);
  });

  test('returns false for non-existent scan', () => {
    expect(removeScan(ctx, 'nope')).toBe(false);
  });
});

describe('Database — clearAllScans', () => {
  let ctx;
  beforeEach(() => { ctx = createTestDb(); });
  afterEach(() => { ctx.db.close(); });

  test('removes all scans and returns count', () => {
    const r = { success: true, language: 'js', securityScore: 80, riskLevel: 'low', summary: '', vulnerabilities: [{ type: 'XSS', severity: 'medium', owasp: '', cwe: '', description: '', location: '', confidence: 0.8 }] };
    saveScan(ctx, 'clear-1', r, 'code1', null);
    saveScan(ctx, 'clear-2', r, 'code2', null);
    saveScan(ctx, 'clear-3', r, 'code3', null);
    expect(scanCount(ctx)).toBe(3);

    const removed = clearAllScans(ctx);
    expect(removed).toBe(3);
    expect(scanCount(ctx)).toBe(0);
    // Vulnerabilities should also be cascaded away
    expect(ctx.stmts.selectVulns.all('clear-1')).toHaveLength(0);
    expect(ctx.stmts.selectVulns.all('clear-2')).toHaveLength(0);
  });

  test('returns 0 when no scans exist', () => {
    expect(clearAllScans(ctx)).toBe(0);
  });
});
