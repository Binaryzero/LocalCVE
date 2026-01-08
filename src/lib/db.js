import { DuckDBInstance } from '@duckdb/node-api';
import path from 'path';

const dbPath = path.resolve(process.cwd(), 'cve.duckdb');

// Create DuckDB instance and connection
let instance;
let connection;
let connectionAge = 0;
const MAX_CONNECTION_OPS = 500; // Recreate connection frequently to avoid DuckDB instability

// Promisified wrapper for DuckDB operations - compatible with better-sqlite3 API patterns
class DuckDBWrapper {
  constructor() {
    this.preparedStatements = new Map();
    this.operationCount = 0;
    this.inTransaction = false; // Track transaction state to avoid connection refresh during tx
    this.queryQueue = Promise.resolve(); // Serialize queries to avoid concurrent access issues
  }

  // Serialize database operations to prevent concurrent access instability
  async _serializedOperation(operation) {
    // Queue this operation after all pending operations
    const result = this.queryQueue.then(operation).catch(err => {
      // Don't let one failed operation break the queue
      throw err;
    });
    // Update queue to wait for this operation (log errors but don't break the chain)
    this.queryQueue = result.catch((err) => {
      console.error('[DuckDB] Query in queue failed:', err.message);
    });
    return result;
  }

  // Get a fresh connection if needed
  async getConnection() {
    this.operationCount++;
    // Periodically refresh connection to avoid DuckDB instability
    // BUT never during an active transaction - that would corrupt state
    if (this.operationCount > MAX_CONNECTION_OPS && !this.inTransaction) {
      try {
        console.log('[DuckDB] Refreshing connection after', this.operationCount, 'operations');
        connection = await instance.connect();
        this.operationCount = 0;
      } catch (err) {
        console.error('[DuckDB] Error refreshing connection:', err);
        // Continue with existing connection
      }
    }
    return connection;
  }

  // Execute SQL and return all results as row objects
  async all(sql, ...params) {
    const namedParams = this._buildNamedParams(sql, params);

    return this._serializedOperation(async () => {
      // Try up to 2 times with connection refresh on failure
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const conn = await this.getConnection();
          const reader = await conn.runAndReadAll(sql, namedParams);
          return reader.getRowObjects() || [];
        } catch (err) {
          if (attempt === 0 && err.message && err.message.includes('Failed to execute')) {
            console.log('[DuckDB] Query failed, refreshing connection and retrying...');
            try {
              connection = await instance.connect();
              this.operationCount = 0;
            } catch (refreshErr) {
              console.error('[DuckDB] Connection refresh failed:', refreshErr);
            }
            continue; // Retry with fresh connection
          }
          console.error('[DuckDB] Query error:', sql, err);
          throw err;
        }
      }
    });
  }

  // Execute SQL and return first result
  async get(sql, ...params) {
    const results = await this.all(sql, ...params);
    return results.length > 0 ? results[0] : null;
  }

  // Execute SQL (INSERT/UPDATE/DELETE) and return changes info
  async run(sql, ...params) {
    const namedParams = this._buildNamedParams(sql, params);

    return this._serializedOperation(async () => {
      // Try up to 2 times with connection refresh on failure (but not during transactions)
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const conn = await this.getConnection();
          await conn.run(sql, namedParams);
          // DuckDB doesn't return changes count easily, returning placeholder
          return { changes: 0, lastID: 0 };
        } catch (err) {
          if (attempt === 0 && !this.inTransaction && err.message && err.message.includes('Failed to execute')) {
            console.log('[DuckDB] Run failed, refreshing connection and retrying...');
            try {
              connection = await instance.connect();
              this.operationCount = 0;
            } catch (refreshErr) {
              console.error('[DuckDB] Connection refresh failed:', refreshErr);
            }
            continue; // Retry with fresh connection
          }
          console.error('[DuckDB] Run error:', sql, err);
          throw err;
        }
      }
    });
  }

  // Build named parameter object from positional params
  _buildNamedParams(sql, params) {
    if (params.length === 0) return {};

    // If first param is an object (named params), use it directly
    if (params.length === 1 && typeof params[0] === 'object' && params[0] !== null && !Array.isArray(params[0])) {
      return params[0];
    }

    // Convert positional params to numbered params
    const result = {};
    params.forEach((val, idx) => {
      result[idx + 1] = val;
    });
    return result;
  }

  // Execute multiple SQL statements
  async execSQL(sql) {
    const statements = sql.split(';').filter(s => s.trim());
    for (const stmt of statements) {
      if (stmt.trim()) {
        const conn = await this.getConnection();
        await conn.run(stmt);
      }
    }
  }

  // Prepare a statement for repeated execution
  prepare(sql) {
    const self = this;
    // Convert @name syntax to $name for DuckDB compatibility
    const processedSql = sql.replace(/@(\w+)/g, '$$$1');

    return {
      sql: processedSql,
      run: async (...params) => {
        const namedParams = self._buildNamedParams(processedSql, params);
        const conn = await self.getConnection();
        await conn.run(processedSql, namedParams);
        return { changes: 0, lastID: 0 };
      },
      get: async (...params) => {
        const namedParams = self._buildNamedParams(processedSql, params);
        const conn = await self.getConnection();
        const reader = await conn.runAndReadAll(processedSql, namedParams);
        const rows = reader.getRowObjects() || [];
        return rows.length > 0 ? rows[0] : null;
      },
      all: async (...params) => {
        const namedParams = self._buildNamedParams(processedSql, params);
        const conn = await self.getConnection();
        const reader = await conn.runAndReadAll(processedSql, namedParams);
        return reader.getRowObjects() || [];
      }
    };
  }

  // Transaction wrapper
  async transaction(fn) {
    const conn = await this.getConnection();
    this.inTransaction = true;
    try {
      await conn.run('BEGIN TRANSACTION');
      const result = await fn();
      await conn.run('COMMIT');
      return result;
    } catch (err) {
      try {
        await conn.run('ROLLBACK');
      } catch (rollbackErr) {
        console.error('[DuckDB] Rollback failed:', rollbackErr);
      }
      throw err;
    } finally {
      this.inTransaction = false;
    }
  }

  // Get column info for a table (replaces SQLite's pragma table_info)
  async getTableColumns(tableName) {
    const conn = await this.getConnection();
    const reader = await conn.runAndReadAll(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = $1
    `, { 1: tableName });
    const rows = reader.getRowObjects() || [];
    return rows.map(r => r.column_name);
  }

  // Check if a table exists
  async tableExists(tableName) {
    const conn = await this.getConnection();
    const reader = await conn.runAndReadAll(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_name = $1
    `, { 1: tableName });
    const rows = reader.getRowObjects() || [];
    return rows.length > 0;
  }

  // Force connection refresh
  async refreshConnection() {
    try {
      connection = await instance.connect();
      this.operationCount = 0;
      console.log('[DuckDB] Connection manually refreshed');
    } catch (err) {
      console.error('[DuckDB] Error refreshing connection:', err);
      throw err;
    }
  }
}

let db;

// Schema initialization - DuckDB compatible
// NOTE: Foreign key constraints (ON DELETE CASCADE) were intentionally removed during SQLite->DuckDB migration.
// Rationale: (1) CVEs are never deleted in normal operation - they are only updated/added during ingestion.
// (2) DuckDB's FK handling adds overhead to bulk inserts (326k+ CVEs).
// (3) Orphaned records are cleaned up during full re-ingestion via "DELETE FROM table WHERE cve_id = ?".
// If CVE deletion is needed in the future, implement cascade delete in application layer.
const initSql = `
CREATE TABLE IF NOT EXISTS cves (
  id VARCHAR PRIMARY KEY,
  description TEXT,
  published VARCHAR,
  last_modified VARCHAR,
  vuln_status VARCHAR,
  normalized_hash VARCHAR,
  json TEXT,
  title TEXT,
  source_advisory VARCHAR
);

CREATE TABLE IF NOT EXISTS metrics (
  cve_id VARCHAR,
  cvss_version VARCHAR,
  score DOUBLE,
  severity VARCHAR,
  vector_string VARCHAR
);
CREATE INDEX IF NOT EXISTS idx_metrics_cve_id ON metrics(cve_id);

CREATE TABLE IF NOT EXISTS cve_references (
  cve_id VARCHAR,
  url TEXT,
  tags TEXT
);

CREATE TABLE IF NOT EXISTS configs (
  cve_id VARCHAR,
  nodes TEXT
);

CREATE SEQUENCE IF NOT EXISTS job_runs_id_seq;
CREATE TABLE IF NOT EXISTS job_runs (
  id INTEGER PRIMARY KEY DEFAULT nextval('job_runs_id_seq'),
  start_time VARCHAR,
  end_time VARCHAR,
  status VARCHAR,
  items_processed INTEGER,
  error TEXT,
  progress_percent INTEGER DEFAULT 0,
  items_added INTEGER DEFAULT 0,
  items_updated INTEGER DEFAULT 0,
  items_unchanged INTEGER DEFAULT 0,
  current_phase VARCHAR,
  cancel_requested INTEGER DEFAULT 0,
  last_heartbeat VARCHAR,
  total_files INTEGER
);

CREATE SEQUENCE IF NOT EXISTS job_logs_id_seq;
CREATE TABLE IF NOT EXISTS job_logs (
  id INTEGER PRIMARY KEY DEFAULT nextval('job_logs_id_seq'),
  job_id INTEGER NOT NULL,
  timestamp VARCHAR NOT NULL,
  level VARCHAR NOT NULL,
  message TEXT NOT NULL,
  metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_job_logs_job_id ON job_logs(job_id);

CREATE SEQUENCE IF NOT EXISTS cve_changes_id_seq;
CREATE TABLE IF NOT EXISTS cve_changes (
  id INTEGER PRIMARY KEY DEFAULT nextval('cve_changes_id_seq'),
  cve_id VARCHAR,
  change_date VARCHAR,
  diff_json TEXT
);

CREATE SEQUENCE IF NOT EXISTS cve_cwes_id_seq;
CREATE TABLE IF NOT EXISTS cve_cwes (
  id INTEGER PRIMARY KEY DEFAULT nextval('cve_cwes_id_seq'),
  cve_id VARCHAR NOT NULL,
  cwe_id VARCHAR NOT NULL,
  description TEXT,
  UNIQUE(cve_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_cwes_cve ON cve_cwes(cve_id);

CREATE SEQUENCE IF NOT EXISTS cve_capec_id_seq;
CREATE TABLE IF NOT EXISTS cve_capec (
  id INTEGER PRIMARY KEY DEFAULT nextval('cve_capec_id_seq'),
  cve_id VARCHAR NOT NULL,
  capec_id VARCHAR NOT NULL,
  description TEXT,
  UNIQUE(cve_id, capec_id)
);
CREATE INDEX IF NOT EXISTS idx_capec_cve ON cve_capec(cve_id);

CREATE SEQUENCE IF NOT EXISTS cve_ssvc_id_seq;
CREATE TABLE IF NOT EXISTS cve_ssvc (
  id INTEGER PRIMARY KEY DEFAULT nextval('cve_ssvc_id_seq'),
  cve_id VARCHAR NOT NULL,
  exploitation VARCHAR,
  automatable VARCHAR,
  technical_impact VARCHAR,
  provider VARCHAR,
  UNIQUE(cve_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_ssvc_cve ON cve_ssvc(cve_id);

CREATE SEQUENCE IF NOT EXISTS cve_workarounds_id_seq;
CREATE TABLE IF NOT EXISTS cve_workarounds (
  id INTEGER PRIMARY KEY DEFAULT nextval('cve_workarounds_id_seq'),
  cve_id VARCHAR NOT NULL,
  workaround_text TEXT NOT NULL,
  language VARCHAR DEFAULT 'en'
);
CREATE INDEX IF NOT EXISTS idx_workarounds_cve ON cve_workarounds(cve_id);

CREATE SEQUENCE IF NOT EXISTS cve_solutions_id_seq;
CREATE TABLE IF NOT EXISTS cve_solutions (
  id INTEGER PRIMARY KEY DEFAULT nextval('cve_solutions_id_seq'),
  cve_id VARCHAR NOT NULL,
  solution_text TEXT NOT NULL,
  language VARCHAR DEFAULT 'en'
);
CREATE INDEX IF NOT EXISTS idx_solutions_cve ON cve_solutions(cve_id);

CREATE TABLE IF NOT EXISTS cve_products (
  cve_id VARCHAR NOT NULL,
  vendor VARCHAR NOT NULL,
  product VARCHAR NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cve_products_cve ON cve_products(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_products_vendor ON cve_products(vendor);
CREATE INDEX IF NOT EXISTS idx_cve_products_product ON cve_products(product);

CREATE SEQUENCE IF NOT EXISTS watchlists_id_seq;
CREATE TABLE IF NOT EXISTS watchlists (
  id INTEGER PRIMARY KEY DEFAULT nextval('watchlists_id_seq'),
  name VARCHAR,
  query_json TEXT,
  enabled INTEGER DEFAULT 1,
  last_run VARCHAR,
  match_count INTEGER DEFAULT 0
);

CREATE SEQUENCE IF NOT EXISTS alerts_id_seq;
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY DEFAULT nextval('alerts_id_seq'),
  cve_id VARCHAR,
  watchlist_id INTEGER,
  watchlist_name VARCHAR,
  type VARCHAR,
  created_at VARCHAR,
  read INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS system_metadata (
  key VARCHAR PRIMARY KEY,
  value TEXT
);
`;

// Initialize database schema
async function initializeDatabase() {
  try {
    // Create DuckDB instance
    instance = await DuckDBInstance.create(dbPath);
    connection = await instance.connect();
    db = new DuckDBWrapper();

    // Execute schema creation - split into individual statements
    const statements = initSql.split(';').filter(s => s.trim());
    for (const stmt of statements) {
      if (stmt.trim()) {
        try {
          await connection.run(stmt);
        } catch (err) {
          // Ignore errors for IF NOT EXISTS statements
          if (!err.message?.includes('already exists')) {
            console.warn('[DuckDB] Schema statement warning:', err.message);
          }
        }
      }
    }

    // Check and add missing columns for migrations
    const jobRunsColumns = await db.getTableColumns('job_runs');
    const newJobRunsColumns = [
      { name: 'progress_percent', def: 'INTEGER DEFAULT 0' },
      { name: 'items_added', def: 'INTEGER DEFAULT 0' },
      { name: 'items_updated', def: 'INTEGER DEFAULT 0' },
      { name: 'items_unchanged', def: 'INTEGER DEFAULT 0' },
      { name: 'current_phase', def: 'VARCHAR' },
      { name: 'cancel_requested', def: 'INTEGER DEFAULT 0' },
      { name: 'last_heartbeat', def: 'VARCHAR' },
      { name: 'total_files', def: 'INTEGER' }
    ];

    for (const col of newJobRunsColumns) {
      if (!jobRunsColumns.includes(col.name)) {
        try {
          await connection.run(`ALTER TABLE job_runs ADD COLUMN ${col.name} ${col.def}`);
        } catch (e) {
          // Column might already exist
        }
      }
    }

    // Migrate cves table
    const cvesColumns = await db.getTableColumns('cves');
    const newCvesColumns = [
      { name: 'title', def: 'TEXT' },
      { name: 'source_advisory', def: 'VARCHAR' }
    ];

    for (const col of newCvesColumns) {
      if (!cvesColumns.includes(col.name)) {
        try {
          await connection.run(`ALTER TABLE cves ADD COLUMN ${col.name} ${col.def}`);
        } catch (e) {
          // Column might already exist
        }
      }
    }

    // Migrate cve_references table
    const refsColumns = await db.getTableColumns('cve_references');
    if (!refsColumns.includes('tags')) {
      try {
        await connection.run('ALTER TABLE cve_references ADD COLUMN tags TEXT');
      } catch (e) {
        // Column might already exist
      }
    }

    // Load FTS extension
    try {
      await connection.run('INSTALL fts');
      await connection.run('LOAD fts');
      console.log('[DuckDB] FTS extension loaded');
    } catch (err) {
      console.warn('[DuckDB] FTS extension warning:', err.message);
    }

    // Create FTS index on cves table (if not exists - will be created when CVEs are ingested)
    // Note: DuckDB FTS requires at least one row to create the index, so we defer this
    // The index will be created/updated after ingestion in nvd.js

    console.log('[DuckDB] Database initialized successfully');
    return db;
  } catch (err) {
    console.error('[DuckDB] Error initializing database:', err);
    throw err;
  }
}

// Helper to create/recreate FTS index after data ingestion
async function rebuildFtsIndex() {
  try {
    await connection.run('LOAD fts');
    // Drop existing index if any
    try {
      await connection.run("PRAGMA drop_fts_index('cves')");
    } catch (e) {
      // Index might not exist yet
    }
    // Create new FTS index on id and description
    await connection.run("PRAGMA create_fts_index('cves', 'id', 'description')");
    console.log('[DuckDB] FTS index rebuilt');
  } catch (err) {
    console.error('[DuckDB] Error rebuilding FTS index:', err);
    throw err;
  }
}

// Initialize on module load
const initPromise = initializeDatabase();

// Helper to get the db instance (must call after initPromise resolves)
function getDb() {
  if (!db) {
    throw new Error('Database not initialized. Await initPromise first.');
  }
  return db;
}

// Export the db getter, initialization promise, and helpers
export default getDb;
export { initPromise, getDb as db, rebuildFtsIndex };
