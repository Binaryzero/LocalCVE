import Database from 'better-sqlite3';
import path from 'path';

const dbPath = path.resolve(process.cwd(), 'cve.sqlite');

let db;
let bulkMode = false;

// Schema initialization - SQLite with FTS5
const initSql = `
CREATE TABLE IF NOT EXISTS cves (
  id TEXT PRIMARY KEY,
  description TEXT,
  published TEXT,
  last_modified TEXT,
  vuln_status TEXT,
  normalized_hash TEXT,
  json TEXT,
  title TEXT,
  source_advisory TEXT
);

CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  cvss_version TEXT,
  score REAL,
  severity TEXT,
  vector_string TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_metrics_cve_id ON metrics(cve_id);

CREATE TABLE IF NOT EXISTS cve_references (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  url TEXT,
  tags TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_refs_cve_id ON cve_references(cve_id);

CREATE TABLE IF NOT EXISTS configs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  nodes TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_configs_cve_id ON configs(cve_id);

CREATE TABLE IF NOT EXISTS job_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  start_time TEXT,
  end_time TEXT,
  status TEXT,
  items_processed INTEGER,
  error TEXT,
  progress_percent INTEGER DEFAULT 0,
  items_added INTEGER DEFAULT 0,
  items_updated INTEGER DEFAULT 0,
  items_unchanged INTEGER DEFAULT 0,
  current_phase TEXT,
  cancel_requested INTEGER DEFAULT 0,
  last_heartbeat TEXT,
  total_files INTEGER
);

CREATE TABLE IF NOT EXISTS job_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  timestamp TEXT NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  metadata TEXT,
  FOREIGN KEY (job_id) REFERENCES job_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_job_logs_job_id ON job_logs(job_id);

CREATE TABLE IF NOT EXISTS cve_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  change_date TEXT,
  diff_json TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_changes_cve_id ON cve_changes(cve_id);

CREATE TABLE IF NOT EXISTS cve_cwes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  cwe_id TEXT NOT NULL,
  description TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE,
  UNIQUE(cve_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_cwes_cve ON cve_cwes(cve_id);

CREATE TABLE IF NOT EXISTS cve_capec (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  capec_id TEXT NOT NULL,
  description TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE,
  UNIQUE(cve_id, capec_id)
);
CREATE INDEX IF NOT EXISTS idx_capec_cve ON cve_capec(cve_id);

CREATE TABLE IF NOT EXISTS cve_ssvc (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  exploitation TEXT,
  automatable TEXT,
  technical_impact TEXT,
  provider TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE,
  UNIQUE(cve_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_ssvc_cve ON cve_ssvc(cve_id);

CREATE TABLE IF NOT EXISTS cve_workarounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  workaround_text TEXT NOT NULL,
  language TEXT DEFAULT 'en',
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_workarounds_cve ON cve_workarounds(cve_id);

CREATE TABLE IF NOT EXISTS cve_solutions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  solution_text TEXT NOT NULL,
  language TEXT DEFAULT 'en',
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_solutions_cve ON cve_solutions(cve_id);

CREATE TABLE IF NOT EXISTS cve_products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  vendor TEXT NOT NULL,
  product TEXT NOT NULL,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cve_products_cve ON cve_products(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_products_vendor ON cve_products(vendor);
CREATE INDEX IF NOT EXISTS idx_cve_products_product ON cve_products(product);

CREATE TABLE IF NOT EXISTS cve_temporal (
  cve_id TEXT PRIMARY KEY,
  epss REAL,
  exploit_maturity TEXT,
  cvss_bt_score REAL,
  cvss_bt_severity TEXT,
  cisa_kev INTEGER DEFAULT 0,
  vulncheck_kev INTEGER DEFAULT 0,
  exploitdb INTEGER DEFAULT 0,
  metasploit INTEGER DEFAULT 0,
  nuclei INTEGER DEFAULT 0,
  poc_github INTEGER DEFAULT 0,
  last_updated TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_temporal_epss ON cve_temporal(epss);
CREATE INDEX IF NOT EXISTS idx_temporal_maturity ON cve_temporal(exploit_maturity);

CREATE TABLE IF NOT EXISTS cve_exploits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  source TEXT NOT NULL,
  url TEXT NOT NULL,
  description TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE,
  UNIQUE(cve_id, url)
);
CREATE INDEX IF NOT EXISTS idx_exploits_cve ON cve_exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_source ON cve_exploits(source);

CREATE TABLE IF NOT EXISTS watchlists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  query_json TEXT,
  enabled INTEGER DEFAULT 1,
  last_run TEXT,
  match_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT,
  watchlist_id INTEGER,
  watchlist_name TEXT,
  type TEXT,
  created_at TEXT,
  read INTEGER DEFAULT 0,
  FOREIGN KEY (watchlist_id) REFERENCES watchlists(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alerts_cve_id ON alerts(cve_id);

CREATE TABLE IF NOT EXISTS system_metadata (
  key TEXT PRIMARY KEY,
  value TEXT
);

-- FTS5 virtual table for full-text search (external content mode)
CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
  id,
  description,
  refs,
  tokenize='porter unicode61'
);
`;

// Initialize database with performance optimizations
function initializeDatabase() {
  try {
    db = new Database(dbPath);

    // Performance optimizations
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');
    db.pragma('cache_size = -64000');     // 64MB cache
    db.pragma('mmap_size = 268435456');   // 256MB memory-mapped I/O
    db.pragma('temp_store = MEMORY');
    db.pragma('foreign_keys = ON');

    // Schema creation
    db.exec(initSql);

    console.log('[SQLite] Database initialized successfully');
    return db;
  } catch (err) {
    console.error('[SQLite] Error initializing database:', err);
    throw err;
  }
}

// Enable bulk load mode - maximum speed, reduced safety
function enableBulkMode() {
  if (bulkMode) return;
  bulkMode = true;
  db.pragma('synchronous = OFF');
  db.pragma('journal_mode = MEMORY');
  db.pragma('foreign_keys = OFF');
  console.log('[SQLite] Bulk mode enabled');
}

// Disable bulk load mode - restore safe settings
function disableBulkMode() {
  if (!bulkMode) return;
  bulkMode = false;
  db.pragma('foreign_keys = ON');
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  console.log('[SQLite] Bulk mode disabled');
}

// Rebuild FTS5 index from cves table
function rebuildFtsIndex() {
  console.log('[SQLite] Rebuilding FTS5 index...');
  const start = Date.now();

  // Clear existing FTS data
  db.exec('DELETE FROM cves_fts');

  // Rebuild from cves and references
  db.exec(`
    INSERT INTO cves_fts (id, description, refs)
    SELECT
      c.id,
      c.description,
      COALESCE(GROUP_CONCAT(r.url, ' '), '')
    FROM cves c
    LEFT JOIN cve_references r ON r.cve_id = c.id
    GROUP BY c.id
  `);

  console.log('[SQLite] FTS5 index rebuilt in ' + (Date.now() - start) + 'ms');
}

// Wrapper class for async-like API compatibility (sync under the hood)
class SQLiteWrapper {
  // All methods are sync but we keep async signatures for compatibility
  async all(sql, ...params) {
    return db.prepare(sql).all(...params);
  }

  async get(sql, ...params) {
    return db.prepare(sql).get(...params);
  }

  async run(sql, ...params) {
    const result = db.prepare(sql).run(...params);
    return { changes: result.changes, lastID: result.lastInsertRowid };
  }

  prepare(sql) {
    const stmt = db.prepare(sql);
    return {
      run: (...params) => stmt.run(...params),
      get: (...params) => stmt.get(...params),
      all: (...params) => stmt.all(...params)
    };
  }

  // Transaction with manual BEGIN/COMMIT to support async functions
  async transaction(fn) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = await fn();
      db.exec('COMMIT');
      return result;
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  // Synchronous transaction for pure sync code
  transactionSync(fn) {
    return db.transaction(fn)();
  }

  async execSQL(sql) {
    db.exec(sql);
  }
}

// Initialize on module load
const wrapper = new SQLiteWrapper();
initializeDatabase();

// Initialization promise (resolves immediately for sync SQLite)
const initPromise = Promise.resolve(wrapper);

// Helper to get the db wrapper
function getDb() {
  return wrapper;
}

// Export for direct access when needed
export default getDb;
export { initPromise, getDb as db, rebuildFtsIndex, enableBulkMode, disableBulkMode };
