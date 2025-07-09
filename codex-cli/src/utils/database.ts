import Database from "better-sqlite3";
import { join } from "path";
import { CONFIG_DIR } from "./config.js";
import { mkdirSync } from "fs";

// Ensure config directory exists
try {
  mkdirSync(CONFIG_DIR, { recursive: true });
} catch {
  // Directory already exists
}

const DB_PATH = join(CONFIG_DIR, "bugbounty.db");
export const db = new Database(DB_PATH);

// Enable foreign keys
db.pragma("foreign_keys = ON");

// Create tables for bug bounty operations
export function initDatabase(): void {
  // Targets table - stores domains/URLs to scan
  db.exec(`
    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL UNIQUE,
      description TEXT,
      api_keys TEXT, -- JSON string of API keys
      auth_cookies TEXT, -- JSON string of authentication cookies
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      status TEXT DEFAULT 'active' -- active, paused, completed
    )
  `);

  // Scans table - tracks scanning operations
  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id INTEGER NOT NULL,
      scan_type TEXT NOT NULL, -- subdomain, port, vuln, web_crawl, etc.
      status TEXT DEFAULT 'pending', -- pending, running, completed, failed
      command TEXT, -- Command that was executed
      started_at DATETIME,
      completed_at DATETIME,
      result_data TEXT, -- JSON string of results
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
    )
  `);

  // Vulnerabilities table - stores discovered vulnerabilities
  db.exec(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id INTEGER NOT NULL,
      scan_id INTEGER,
      vuln_type TEXT NOT NULL, -- xss, sqli, idor, xxe, etc.
      severity TEXT NOT NULL, -- critical, high, medium, low, info
      title TEXT NOT NULL,
      description TEXT,
      url TEXT,
      payload TEXT,
      proof_of_concept TEXT,
      cwe_id TEXT, -- CWE identifier
      cvss_score REAL,
      discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      verified BOOLEAN DEFAULT FALSE,
      false_positive BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE,
      FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE SET NULL
    )
  `);

  // Web APIs table - stores discovered API endpoints
  db.exec(`
    CREATE TABLE IF NOT EXISTS web_apis (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id INTEGER NOT NULL,
      method TEXT NOT NULL, -- GET, POST, PUT, DELETE, etc.
      endpoint TEXT NOT NULL,
      parameters TEXT, -- JSON string of parameters
      headers TEXT, -- JSON string of headers
      response_type TEXT, -- JSON, XML, HTML, etc.
      auth_required BOOLEAN DEFAULT FALSE,
      discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
    )
  `);

  // Scan configurations for self-improvement
  db.exec(`
    CREATE TABLE IF NOT EXISTS scan_configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tool_name TEXT NOT NULL,
      config_data TEXT NOT NULL, -- JSON string of configuration
      success_rate REAL DEFAULT 0.0, -- Learning metric
      avg_execution_time INTEGER DEFAULT 0, -- Average time in seconds
      last_used DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create indexes for better performance
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain);
    CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
    CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
    CREATE INDEX IF NOT EXISTS idx_vulns_target_id ON vulnerabilities(target_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type);
    CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_apis_target_id ON web_apis(target_id);
  `);
}

// Target management functions
export interface Target {
  id?: number;
  domain: string;
  description?: string;
  api_keys?: Record<string, string>;
  auth_cookies?: Record<string, string>;
  created_at?: string;
  updated_at?: string;
  status?: "active" | "paused" | "completed";
}

export function addTarget(target: Target): number {
  const stmt = db.prepare(`
    INSERT INTO targets (domain, description, api_keys, auth_cookies, status)
    VALUES (?, ?, ?, ?, ?)
  `);
  
  const result = stmt.run(
    target.domain,
    target.description || null,
    target.api_keys ? JSON.stringify(target.api_keys) : null,
    target.auth_cookies ? JSON.stringify(target.auth_cookies) : null,
    target.status || "active"
  );
  
  return result.lastInsertRowid as number;
}

export function getTargets(): Target[] {
  const stmt = db.prepare("SELECT * FROM targets ORDER BY created_at DESC");
  const rows = stmt.all() as any[];
  
  return rows.map(row => ({
    ...row,
    api_keys: row.api_keys ? JSON.parse(row.api_keys) : {},
    auth_cookies: row.auth_cookies ? JSON.parse(row.auth_cookies) : {},
  }));
}

export function getTarget(id: number): Target | null {
  const stmt = db.prepare("SELECT * FROM targets WHERE id = ?");
  const row = stmt.get(id) as any;
  
  if (!row) return null;
  
  return {
    ...row,
    api_keys: row.api_keys ? JSON.parse(row.api_keys) : {},
    auth_cookies: row.auth_cookies ? JSON.parse(row.auth_cookies) : {},
  };
}

export function updateTarget(id: number, updates: Partial<Target>): void {
  const fields: string[] = [];
  const values: any[] = [];
  
  if (updates.description !== undefined) {
    fields.push("description = ?");
    values.push(updates.description);
  }
  
  if (updates.api_keys !== undefined) {
    fields.push("api_keys = ?");
    values.push(JSON.stringify(updates.api_keys));
  }
  
  if (updates.auth_cookies !== undefined) {
    fields.push("auth_cookies = ?");
    values.push(JSON.stringify(updates.auth_cookies));
  }
  
  if (updates.status !== undefined) {
    fields.push("status = ?");
    values.push(updates.status);
  }
  
  if (fields.length === 0) return;
  
  fields.push("updated_at = CURRENT_TIMESTAMP");
  values.push(id);
  
  const sql = `UPDATE targets SET ${fields.join(", ")} WHERE id = ?`;
  const stmt = db.prepare(sql);
  stmt.run(...values);
}

// Scan management functions
export interface Scan {
  id?: number;
  target_id: number;
  scan_type: string;
  status?: "pending" | "running" | "completed" | "failed";
  command?: string;
  started_at?: string;
  completed_at?: string;
  result_data?: any;
  created_at?: string;
}

export function addScan(scan: Scan): number {
  const stmt = db.prepare(`
    INSERT INTO scans (target_id, scan_type, status, command, result_data)
    VALUES (?, ?, ?, ?, ?)
  `);
  
  const result = stmt.run(
    scan.target_id,
    scan.scan_type,
    scan.status || "pending",
    scan.command || null,
    scan.result_data ? JSON.stringify(scan.result_data) : null
  );
  
  return result.lastInsertRowid as number;
}

export function updateScanStatus(
  id: number, 
  status: "pending" | "running" | "completed" | "failed",
  result_data?: any
): void {
  const updates: string[] = ["status = ?"];
  const values: any[] = [status];
  
  if (status === "running" && !getScan(id)?.started_at) {
    updates.push("started_at = CURRENT_TIMESTAMP");
  }
  
  if (status === "completed" || status === "failed") {
    updates.push("completed_at = CURRENT_TIMESTAMP");
  }
  
  if (result_data !== undefined) {
    updates.push("result_data = ?");
    values.push(JSON.stringify(result_data));
  }
  
  values.push(id);
  
  const sql = `UPDATE scans SET ${updates.join(", ")} WHERE id = ?`;
  const stmt = db.prepare(sql);
  stmt.run(...values);
}

export function getScan(id: number): Scan | null {
  const stmt = db.prepare("SELECT * FROM scans WHERE id = ?");
  const row = stmt.get(id) as any;
  
  if (!row) return null;
  
  return {
    ...row,
    result_data: row.result_data ? JSON.parse(row.result_data) : null,
  };
}

export function getScansForTarget(targetId: number): Scan[] {
  const stmt = db.prepare(`
    SELECT * FROM scans 
    WHERE target_id = ? 
    ORDER BY created_at DESC
  `);
  const rows = stmt.all(targetId) as any[];
  
  return rows.map(row => ({
    ...row,
    result_data: row.result_data ? JSON.parse(row.result_data) : null,
  }));
}

// Vulnerability management functions
export interface Vulnerability {
  id?: number;
  target_id: number;
  scan_id?: number;
  vuln_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description?: string;
  url?: string;
  payload?: string;
  proof_of_concept?: string;
  cwe_id?: string;
  cvss_score?: number;
  discovered_at?: string;
  verified?: boolean;
  false_positive?: boolean;
}

export function addVulnerability(vuln: Vulnerability): number {
  const stmt = db.prepare(`
    INSERT INTO vulnerabilities (
      target_id, scan_id, vuln_type, severity, title, description,
      url, payload, proof_of_concept, cwe_id, cvss_score, verified, false_positive
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  const result = stmt.run(
    vuln.target_id,
    vuln.scan_id || null,
    vuln.vuln_type,
    vuln.severity,
    vuln.title,
    vuln.description || null,
    vuln.url || null,
    vuln.payload || null,
    vuln.proof_of_concept || null,
    vuln.cwe_id || null,
    vuln.cvss_score || null,
    vuln.verified || false,
    vuln.false_positive || false
  );
  
  return result.lastInsertRowid as number;
}

export function getVulnerabilities(targetId?: number): Vulnerability[] {
  const sql = targetId 
    ? "SELECT * FROM vulnerabilities WHERE target_id = ? ORDER BY discovered_at DESC"
    : "SELECT * FROM vulnerabilities ORDER BY discovered_at DESC";
  
  const stmt = db.prepare(sql);
  const rows = targetId ? stmt.all(targetId) : stmt.all();
  
  return rows as Vulnerability[];
}

// Initialize database on import
initDatabase();