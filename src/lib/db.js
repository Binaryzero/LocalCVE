import Database from 'better-sqlite3';
import path from 'path';

// Ensure data directory exists if you were putting it in a subdir, 
// but here we use root for simplicity as per requirements.
const dbPath = path.resolve(process.cwd(), 'cve.sqlite');

const db = new Database(dbPath); // verbose: console.log for debugging if needed

// Optimize for concurrency and safety
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('temp_store = MEMORY');
db.pragma('cache_size = -64000'); // 64MB cache

// Schema initialization
const initSql = `
CREATE TABLE IF NOT EXISTS cves (
  id TEXT PRIMARY KEY,
  description TEXT,
  published TEXT,
  last_modified TEXT,
  vuln_status TEXT,
  normalized_hash TEXT,
  json TEXT
);
CREATE TABLE IF NOT EXISTS metrics (
  cve_id TEXT,
  cvss_version TEXT,
  score REAL,
  severity TEXT,
  vector_string TEXT,
  FOREIGN KEY(cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS cve_references (
  cve_id TEXT,
  url TEXT,
  FOREIGN KEY(cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS configs (
  cve_id TEXT,
  nodes TEXT,
  FOREIGN KEY(cve_id) REFERENCES cves(id) ON DELETE CASCADE
);

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
  cve_id TEXT,
  change_date TEXT,
  diff_json TEXT,
  FOREIGN KEY(cve_id) REFERENCES cves(id) ON DELETE CASCADE
);
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
  FOREIGN KEY(watchlist_id) REFERENCES watchlists(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS system_metadata (
  key TEXT PRIMARY KEY,
  value TEXT
);
`;

db.exec(initSql);

// Migrate existing job_runs table to add new columns (safe to run multiple times)
const jobRunsColumns = db.pragma('table_info(job_runs)').map(c => c.name);
const newJobRunsColumns = [
  { name: 'progress_percent', def: 'INTEGER DEFAULT 0' },
  { name: 'items_added', def: 'INTEGER DEFAULT 0' },
  { name: 'items_updated', def: 'INTEGER DEFAULT 0' },
  { name: 'items_unchanged', def: 'INTEGER DEFAULT 0' },
  { name: 'current_phase', def: 'TEXT' },
  { name: 'cancel_requested', def: 'INTEGER DEFAULT 0' },
  { name: 'last_heartbeat', def: 'TEXT' },
  { name: 'total_files', def: 'INTEGER' }
];
for (const col of newJobRunsColumns) {
  if (!jobRunsColumns.includes(col.name)) {
    db.prepare(`ALTER TABLE job_runs ADD COLUMN ${col.name} ${col.def}`).run();
  }
}

// FTS Schema Handling
try {
  const isNormal = db.prepare("SELECT type FROM sqlite_master WHERE name='cves_fts' AND sql NOT LIKE 'CREATE VIRTUAL%'").get();
  if (isNormal) {
    console.log('[DB] Dropping legacy cves_fts table to replace with FTS5 Virtual Table');
    db.exec('DROP TABLE cves_fts;');
    db.exec('DROP TABLE IF EXISTS cves_fts_idx;');
  }
} catch (e) {
  console.warn('[DB] Warning checking FTS schema:', e.message);
}

try {
  const tableInfo = db.pragma("table_info(cves_fts)");
  const hasRefs = tableInfo.some(c => c.name === 'refs');
  if (tableInfo.length > 0 && !hasRefs) {
    db.exec('DROP TABLE cves_fts');
  }
} catch (e) { }

db.exec(`
  CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(id, description, refs);
`);

export default db;
