/**
 * Database module — SQLite persistence layer for scan results.
 *
 * Uses better-sqlite3 for synchronous, high-performance access.
 * SQLite was chosen because:
 *   - Zero-configuration, serverless — no separate DB process needed.
 *   - Single-file storage, easy to back up and containerize.
 *   - ACID-compliant with WAL mode for concurrent reads.
 *   - Minimal resource footprint (~2 MB library).
 */

import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import logger from '../utils/logger.js';
import config from '../config/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

const dbPath = config.database?.path
  || path.resolve(__dirname, '../../data/scans.db');

// Ensure data directory exists
import fs from 'fs';
const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbPath);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

logger.info(`Database connected: ${dbPath}`);

// ---------------------------------------------------------------------------
// Schema (auto-migrate on startup)
// ---------------------------------------------------------------------------

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

  CREATE INDEX IF NOT EXISTS idx_vulns_scan   ON vulnerabilities(scan_id);
  CREATE INDEX IF NOT EXISTS idx_scans_ts     ON scans(timestamp);
  CREATE INDEX IF NOT EXISTS idx_scans_lang   ON scans(language);
`);

logger.info('Database schema initialized');

// ---------------------------------------------------------------------------
// Prepared statements (compiled once for performance)
// ---------------------------------------------------------------------------

const insertScan = db.prepare(`
  INSERT INTO scans (scan_id, timestamp, language, filename, code, success,
                     security_score, risk_level, summary, raw_result)
  VALUES (@scanId, @timestamp, @language, @filename, @code, @success,
          @securityScore, @riskLevel, @summary, @rawResult)
`);

const insertVuln = db.prepare(`
  INSERT INTO vulnerabilities (scan_id, type, severity, owasp, cwe,
                               description, location, confidence, raw_json)
  VALUES (@scanId, @type, @severity, @owasp, @cwe,
          @description, @location, @confidence, @rawJson)
`);

const selectScan = db.prepare(`
  SELECT * FROM scans WHERE scan_id = ?
`);

// eslint-disable-next-line no-unused-vars -- prepared for direct vulnerability queries
const selectVulns = db.prepare(`
  SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id
`);

const selectRecentScans = db.prepare(`
  SELECT scan_id, timestamp, language, filename, success,
         security_score, risk_level, summary
  FROM scans
  ORDER BY timestamp DESC
  LIMIT ?
`);

const deleteScan = db.prepare(`
  DELETE FROM scans WHERE scan_id = ?
`);

const countScans = db.prepare(`
  SELECT COUNT(*) as total FROM scans
`);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Coerce a value to a SQLite-safe type (number, string, bigint, Buffer, or null).
 * Arrays and objects are serialised to JSON strings.
 */
function toBindable(val) {
  if (val === undefined || val === null) return null;
  const t = typeof val;
  if (t === 'number' || t === 'string' || t === 'bigint') return val;
  if (Buffer.isBuffer(val)) return val;
  if (Array.isArray(val)) return JSON.stringify(val);
  if (t === 'object') return JSON.stringify(val);
  if (t === 'boolean') return val ? 1 : 0;
  return String(val);
}

/**
 * Save a completed scan and its vulnerabilities inside a transaction.
 */
export function saveScan(scanId, result, code, filename) {
  const timestamp = new Date().toISOString();
  const language = result.language || null;
  const success = result.success ? 1 : 0;
  const securityScore = toBindable(result.securityScore ?? result.security_score ?? null);
  const riskLevel = toBindable(result.riskLevel ?? result.risk_level ?? null);
  const summary = toBindable(result.summary);

  const saveTransaction = db.transaction(() => {
    insertScan.run({
      scanId,
      timestamp,
      language: toBindable(language),
      filename: toBindable(filename),
      code,
      success,
      securityScore,
      riskLevel,
      summary,
      rawResult: JSON.stringify(result),
    });

    const vulns = result.vulnerabilities || [];
    for (const v of vulns) {
      insertVuln.run({
        scanId,
        type: toBindable(v.type || v.title),
        severity: toBindable(v.severity),
        owasp: toBindable(v.owasp || v.owaspCategory),
        cwe: toBindable(v.cwe || v.cweId),
        description: toBindable(v.description),
        location: toBindable(v.location || (v.line ? `Line ${v.line}` : null)),
        confidence: toBindable(v.confidence),
        rawJson: JSON.stringify(v),
      });
    }
  });

  saveTransaction();
  logger.info(`Scan ${scanId} saved to database (${result.vulnerabilities?.length || 0} vulns)`);
}

/**
 * Retrieve a scan and its vulnerabilities by ID.
 * Returns null if not found.
 */
export function getScan(scanId) {
  const row = selectScan.get(scanId);
  if (!row) return null;

  const result = JSON.parse(row.raw_result);
  return {
    ...result,
    scanId: row.scan_id,
    timestamp: row.timestamp,
    code: row.code,
    filename: row.filename,
  };
}

/**
 * List recent scans (metadata only, no code).
 */
export function listScans(limit = 20) {
  return selectRecentScans.all(limit).map((row) => ({
    scanId: row.scan_id,
    timestamp: row.timestamp,
    language: row.language,
    filename: row.filename,
    success: !!row.success,
    securityScore: row.security_score,
    riskLevel: row.risk_level,
    summary: row.summary,
  }));
}

/**
 * Delete a scan and its related vulnerabilities (cascaded).
 */
export function removeScan(scanId) {
  const info = deleteScan.run(scanId);
  return info.changes > 0;
}

/**
 * Return total number of stored scans.
 */
export function scanCount() {
  return countScans.get().total;
}

/**
 * Delete ALL scans and vulnerabilities (clear history).
 * Returns the number of deleted scans.
 */
export function clearAllScans() {
  const info = db.prepare('DELETE FROM scans').run();
  logger.info(`Cleared all scans from database (${info.changes} removed)`);
  return info.changes;
}

/**
 * Gracefully close the database (called on process shutdown).
 */
export function closeDatabase() {
  db.close();
  logger.info('Database connection closed');
}

export default {
  saveScan,
  getScan,
  listScans,
  removeScan,
  scanCount,
  clearAllScans,
  closeDatabase,
};
