import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import getDb, { initPromise, rebuildFtsIndex as dbRebuildFtsIndex } from '../db.js';
import { matchesQuery } from '../matcher.js';

// Database reference (initialized lazily)
let db = null;
async function ensureDb() {
  if (!db) {
    await initPromise;
    db = getDb();
  }
  return db;
}

// --- Configuration ---
const DATA_DIR = path.resolve(process.cwd(), 'data');
const REPO_DIR = path.join(DATA_DIR, 'cvelistV5');
const REPO_URL = 'https://github.com/CVEProject/cvelistV5';
const BATCH_SIZE = 500; // Conservative batch size for DuckDB stability
const BATCH_SIZE_NORMAL = 500; // Same batch size for all operations
const CONCURRENCY = 10; // Parallel file reading/parsing

// Bulk load mode settings (for initial imports / full rescans)
let bulkLoadMode = false;

// --- Helpers ---
const getTimestamp = () => new Date().toISOString();

// BigInt replacer for JSON.stringify (DuckDB returns BigInt for counts)
const bigIntReplacer = (key, value) =>
  typeof value === 'bigint' ? Number(value) : value;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const yieldToEventLoop = () => new Promise((resolve) => setImmediate(resolve));

// Fetch CISA KEV catalog and return a Set of CVE IDs
async function fetchKevCatalog(logger = null) {
    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const data = await response.json();
        const kevSet = new Set(data.vulnerabilities.map(v => v.cveID));
        if (logger) {
            logger.info('Fetched CISA KEV catalog', { count: kevSet.size });
        }
        return kevSet;
    } catch (err) {
        if (logger) {
            logger.warn('Failed to fetch KEV catalog, KEV data will not be populated', { error: err.message });
        }
        return new Set();
    }
}

// --- SSE Client Registry (for real-time log streaming) ---
const sseClients = new Map(); // clientId -> { res, jobId }

export function registerSseClient(clientId, res, jobId) {
    sseClients.set(clientId, { res, jobId });
}

export function unregisterSseClient(clientId) {
    sseClients.delete(clientId);
}

function broadcastToSseClients(jobId, data) {
    for (const [, client] of sseClients) {
        if (client.jobId === jobId) {
            try {
                client.res.write(`data: ${JSON.stringify(data)}\n\n`);
            } catch {
                // Client disconnected, will be cleaned up on next request
            }
        }
    }
}

// --- JobLogger Class ---
class JobLogger {
    constructor(jobId, dbRef) {
        this.jobId = jobId;
        this.db = dbRef;
    }

    async log(level, message, metadata = null) {
        const timestamp = getTimestamp();
        const metadataJson = metadata ? JSON.stringify(metadata, bigIntReplacer) : null;

        // Persist to database
        try {
            if (this.db) {
                await this.db.run(
                    'INSERT INTO job_logs (job_id, timestamp, level, message, metadata) VALUES ($1, $2, $3, $4, $5)',
                    this.jobId, timestamp, level, message, metadataJson
                );
            }
        } catch {
            // DB may not be ready yet during early init
        }

        // Broadcast to SSE clients
        broadcastToSseClients(this.jobId, { timestamp, level, message, metadata });

        // Also log to console for server visibility
        const prefix = `[Job ${this.jobId}]`;
        if (level === 'ERROR') {
            console.error(prefix, message, metadata || '');
        } else if (level === 'WARN') {
            console.warn(prefix, message, metadata || '');
        } else {
            console.log(prefix, message, metadata ? JSON.stringify(metadata, bigIntReplacer) : '');
        }
    }

    async info(message, metadata = null) {
        await this.log('INFO', message, metadata);
    }

    async warn(message, metadata = null) {
        await this.log('WARN', message, metadata);
    }

    async error(message, metadata = null) {
        await this.log('ERROR', message, metadata);
    }
}

function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function computeHash(data) {
    return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

function getDiff(oldObj, newObj) {
    const diff = {};
    const allKeys = new Set([...Object.keys(oldObj), ...Object.keys(newObj)]);
    for (const key of allKeys) {
        if (key === 'hash') continue;
        const oldVal = JSON.stringify(oldObj[key]);
        const newVal = JSON.stringify(newObj[key]);
        if (oldVal !== newVal) diff[key] = { from: oldObj[key], to: newObj[key] };
    }
    return diff;
}

/**
 * Generator that yields file paths recursively.
 * Avoids creating a massive array of 320k strings at once.
 */
function* walk(dir) {
    const files = fs.readdirSync(dir, { withFileTypes: true });
    for (const file of files) {
        const res = path.resolve(dir, file.name);
        if (file.isDirectory()) {
            yield* walk(res);
        } else if (file.name.endsWith('.json') && !file.name.endsWith('delta.json') && !file.name.endsWith('deltaLog.json')) {
            yield res;
        }
    }
}

// --- Git Operations ---
const GIT_CLONE_TIMEOUT = 600000; // 10 minutes
const GIT_PULL_TIMEOUT = 300000;  // 5 minutes
const GIT_MAX_RETRIES = 3;

function gitSpawn(args, cwd = REPO_DIR, timeout = 60000) {
    const result = spawnSync('git', args, {
        cwd,
        encoding: 'utf8',
        timeout,
        maxBuffer: 50 * 1024 * 1024 // 50MB buffer
    });

    if (result.error) {
        if (result.error.code === 'ETIMEDOUT') {
            throw new Error(`Git command timed out after ${timeout}ms: git ${args.join(' ')}`);
        }
        throw new Error(`Git command failed: git ${args.join(' ')} - ${result.error.message}`);
    }

    if (result.status !== 0) {
        throw new Error(`Git command failed with code ${result.status}: git ${args.join(' ')}`);
    }

    return (result.stdout || '').trim();
}

async function gitSpawnWithRetry(args, cwd, timeout, logger, maxRetries = GIT_MAX_RETRIES) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return gitSpawn(args, cwd, timeout);
        } catch (err) {
            if (attempt === maxRetries) {
                await logger.error(`Git operation failed after ${maxRetries} attempts`, { args: args.join(' '), error: err.message });
                throw err;
            }
            const delay = 5000 * attempt; // Exponential backoff
            await logger.warn(`Git operation failed, retrying in ${delay}ms`, { attempt, maxRetries, error: err.message });
            await sleep(delay);
        }
    }
}

async function prepareRepo(logger, checkCancelled, dbRef) {
    ensureDir(DATA_DIR);

    if (!fs.existsSync(path.join(REPO_DIR, '.git'))) {
        await logger.info('Cloning cvelistV5 repository (this may take several minutes)...');

        // Check cancellation before long operation
        if (await checkCancelled()) return { cancelled: true };

        const cloneResult = spawnSync('git', ['clone', '--depth', '1', REPO_URL, REPO_DIR], {
            encoding: 'utf8',
            timeout: GIT_CLONE_TIMEOUT,
            maxBuffer: 50 * 1024 * 1024
        });

        if (cloneResult.error) {
            if (cloneResult.error.code === 'ETIMEDOUT') {
                throw new Error(`Git clone timed out after ${GIT_CLONE_TIMEOUT / 1000} seconds`);
            }
            throw new Error(`Git clone failed: ${cloneResult.error.message}`);
        }

        if (cloneResult.status !== 0) {
            throw new Error(`Git clone failed with code ${cloneResult.status}`);
        }

        const newHash = gitSpawn(['rev-parse', 'HEAD']);
        await logger.info('Repository cloned successfully', { commit: newHash.substring(0, 8) });
        return { mode: 'full', oldHash: null, newHash };
    } else {
        await logger.info('Pulling updates from repository...');
        const oldHash = gitSpawn(['rev-parse', 'HEAD']);

        // Check cancellation before long operation
        if (await checkCancelled()) return { cancelled: true };

        const pullResult = spawnSync('git', ['pull'], {
            cwd: REPO_DIR,
            encoding: 'utf8',
            timeout: GIT_PULL_TIMEOUT,
            maxBuffer: 50 * 1024 * 1024
        });

        if (pullResult.error) {
            if (pullResult.error.code === 'ETIMEDOUT') {
                await logger.warn(`Git pull timed out after ${GIT_PULL_TIMEOUT / 1000}s, using local data`);
            } else {
                await logger.warn('Git pull failed, using local data', { error: pullResult.error.message });
            }
        } else if (pullResult.status !== 0) {
            await logger.warn('Git pull failed, using local data', { exitCode: pullResult.status });
        }

        const newHash = gitSpawn(['rev-parse', 'HEAD']);

        if (oldHash === newHash) {
            // Even if git hasn't changed, check if database is properly populated
            let count = 0;
            try {
                const result = await dbRef.get('SELECT count(*) as c FROM cves');
                count = result ? result.c : 0;
            } catch (e) {
                await logger.warn('Database query failed, forcing full scan', { error: e.message });
                return { mode: 'full', oldHash, newHash };
            }

            // If database is empty or suspiciously small, force full scan
            if (count === 0) {
                await logger.info('Database is empty, forcing full scan');
                return { mode: 'full', oldHash, newHash };
            }

            // Check if we have the stored commit hash to compare against
            let storedHash = null;
            try {
                const result = await dbRef.get("SELECT value FROM system_metadata WHERE key = 'cvelist_commit'");
                storedHash = result ? result.value : null;
            } catch (e) {
                // Table might not exist yet
            }

            // If we don't have a stored hash, we can't be sure database is current
            if (!storedHash) {
                await logger.info('No stored commit hash found, forcing full scan to ensure database is current');
                return { mode: 'full', oldHash, newHash };
            }

            // Only skip if we have a reasonable number of CVEs (>100,000 is full dataset)
            // AND git truly hasn't changed AND we have a stored hash matching current
            if (count < 100000) {
                await logger.info('Database has insufficient CVEs, forcing full scan', { count, expected: '~250k' });
                return { mode: 'full', oldHash, newHash };
            }

            await logger.info('No git changes and database is current, skipping ingestion', { cveCount: count });
            return { mode: 'incremental', oldHash, newHash, noChanges: true };
        }

        // Git pulled new commits - check if we have a stored hash to know where we left off
        let storedHash = null;
        let dbCount = 0;
        try {
            const result = await dbRef.get("SELECT value FROM system_metadata WHERE key = 'cvelist_commit'");
            storedHash = result ? result.value : null;

            const countResult = await dbRef.get('SELECT count(*) as c FROM cves');
            dbCount = countResult ? countResult.c : 0;
        } catch (e) {
            await logger.warn('Database check failed, forcing full scan', { error: e.message });
            return { mode: 'full', oldHash, newHash };
        }

        // If no stored hash, we don't know where we left off - must do full scan
        if (!storedHash) {
            await logger.info('No stored commit hash found after git pull, forcing full scan to catch up');
            return { mode: 'full', oldHash, newHash };
        }

        // If database is suspiciously small, do full scan to ensure completeness
        if (dbCount < 100000) {
            await logger.info('Database has insufficient CVEs after git pull, forcing full scan', { count: dbCount, expected: '~250k' });
            return { mode: 'full', oldHash, newHash };
        }

        // We have a stored hash and good CVE count - use incremental diff from stored hash to new hash
        await logger.info('Incremental update mode', { fromCommit: storedHash.substring(0, 8), toCommit: newHash.substring(0, 8) });
        return { mode: 'incremental', oldHash: storedHash, newHash };
    }
}

function getChangedFiles(oldHash, newHash, logger = null) {
    // Use provided logger or fallback to console
    const log = logger || { info: () => {}, warn: console.warn.bind(console) };
    try {
        const diffOutput = gitSpawn(['diff', '--name-only', oldHash, newHash]);
        const files = diffOutput.split('\n')
            .filter(line => line.startsWith('cves/') && line.endsWith('.json'))
            .map(line => path.join(REPO_DIR, line));
        if (log.info.constructor.name === 'AsyncFunction') {
            // Don't await in sync context, just fire
            log.info('Found changed files', { count: files.length });
        } else {
            log.info('Found changed files', { count: files.length });
        }
        return files;
    } catch (e) {
        if (log.warn.constructor.name === 'AsyncFunction') {
            log.warn('Failed to calculate diff, falling back to full scan', { error: e.message });
        } else {
            log.warn('Failed to calculate diff, falling back to full scan', { error: e.message });
        }
        return null; // Signals full scan needed
    }
}

// --- CVE JSON 5.0 Normalization ---
export function normalizeCve5(raw, kevSet = null) {
    const meta = raw.cveMetadata || {};
    const cna = raw.containers?.cna || {};

    const id = meta.cveId;
    const vulnStatus = meta.state;
    const published = meta.datePublished ? new Date(meta.datePublished).toISOString() : null;
    const lastModified = meta.dateUpdated ? new Date(meta.dateUpdated).toISOString() : null;

    const descObj = cna.descriptions?.find(d => d.lang === 'en') || cna.descriptions?.[0];
    const description = descObj ? descObj.value : 'No description available';

    // Collect all CVSS metrics instead of just the "best" one
    const allMetrics = [];
    let primaryScore = null, primarySeverity = null, primaryVector = null, primaryVersion = null;

    const metrics = cna.metrics || [];
    for (const m of metrics) {
        if (m.cvssV3_1) {
            const metric = {
                version: '3.1',
                score: m.cvssV3_1.baseScore,
                severity: m.cvssV3_1.baseSeverity,
                vector: m.cvssV3_1.vectorString
            };
            allMetrics.push(metric);
            // Set as primary if we haven't set one yet (priority: 3.1 > 3.0 > 2.0)
            if (!primaryVersion) {
                primaryScore = metric.score;
                primarySeverity = metric.severity;
                primaryVector = metric.vector;
                primaryVersion = metric.version;
            }
        }
        if (m.cvssV3_0) {
            const metric = {
                version: '3.0',
                score: m.cvssV3_0.baseScore,
                severity: m.cvssV3_0.baseSeverity,
                vector: m.cvssV3_0.vectorString
            };
            allMetrics.push(metric);
            // Set as primary if we haven't set one yet and this is better than v2.0
            if (!primaryVersion || primaryVersion === '2.0') {
                primaryScore = metric.score;
                primarySeverity = metric.severity;
                primaryVector = metric.vector;
                primaryVersion = metric.version;
            }
        }
        if (m.cvssV2_0) {
            const metric = {
                version: '2.0',
                score: m.cvssV2_0.baseScore,
                severity: m.cvssV2_0.baseSeverity || 'UNKNOWN',
                vector: m.cvssV2_0.vectorString
            };
            allMetrics.push(metric);
            // Set as primary only if we haven't set one yet
            if (!primaryVersion) {
                primaryScore = metric.score;
                primarySeverity = metric.severity;
                primaryVector = metric.vector;
                primaryVersion = metric.version;
            }
        }
    }

    // Extract references with tags
    const refs = (cna.references || []).map(r => ({
        url: r.url,
        tags: r.tags || []
    })).sort((a, b) => a.url.localeCompare(b.url));

    // Keep a simple URL list for backward compatibility (FTS indexing)
    const refUrls = refs.map(r => r.url);

    const configurations = [];
    if (cna.affected) {
        for (const aff of cna.affected) {
            if (aff.product) {
                configurations.push({
                    vendor: aff.vendor || 'n/a',
                    product: aff.product,
                    defaultStatus: aff.defaultStatus || null,
                    modules: aff.modules || [],
                    versions: (aff.versions || []).map(v => ({
                        version: v.version,
                        status: v.status,
                        lessThan: v.lessThan || null,
                        lessThanOrEqual: v.lessThanOrEqual || null,
                        versionType: v.versionType || null
                    }))
                });
            }
        }
    }

    // Extract title (may not always be present)
    const title = cna.title || null;

    // Extract source advisory ID
    const sourceAdvisory = cna.source?.advisory || null;

    // Extract CWE IDs from problemTypes
    const cwes = [];
    for (const pt of (cna.problemTypes || [])) {
        for (const desc of (pt.descriptions || [])) {
            if (desc.cweId) {
                cwes.push({
                    cweId: desc.cweId,
                    description: desc.description || null
                });
            }
        }
    }

    // Extract CAPEC attack patterns from impacts
    const capecs = [];
    for (const impact of (cna.impacts || [])) {
        if (impact.capecId) {
            const capecDesc = impact.descriptions?.find(d => d.lang === 'en')?.value
                           || impact.descriptions?.[0]?.value
                           || null;
            capecs.push({
                capecId: impact.capecId,
                description: capecDesc
            });
        }
    }

    // Extract SSVC from ADP containers (CISA prioritization)
    const ssvc = [];
    const adpContainers = raw.containers?.adp || [];
    for (const adp of adpContainers) {
        const provider = adp.providerMetadata?.shortName;
        for (const metric of (adp.metrics || [])) {
            if (metric.other?.type === 'ssvc' && metric.other?.content?.options) {
                const options = metric.other.content.options;
                const ssvcEntry = {
                    provider: provider || 'Unknown',
                    exploitation: null,
                    automatable: null,
                    technicalImpact: null
                };
                for (const opt of options) {
                    if ('Exploitation' in opt) ssvcEntry.exploitation = opt.Exploitation;
                    if ('Automatable' in opt) ssvcEntry.automatable = opt.Automatable;
                    if ('Technical Impact' in opt) ssvcEntry.technicalImpact = opt['Technical Impact'];
                }
                ssvc.push(ssvcEntry);
            }
        }
    }

    // Extract workarounds (mitigation without patches)
    const workarounds = (cna.workarounds || []).map(w => ({
        text: w.value,
        language: w.lang || 'en'
    }));

    // Extract solutions (official remediation)
    const solutions = (cna.solutions || []).map(s => ({
        text: s.value,
        language: s.lang || 'en'
    }));

    // Create version-specific fields for backward compatibility
    let cvss2Score = null, cvss2Severity = null;
    let cvss30Score = null, cvss30Severity = null;
    let cvss31Score = null, cvss31Severity = null;

    for (const metric of allMetrics) {
        switch (metric.version) {
            case '2.0':
                cvss2Score = metric.score;
                cvss2Severity = metric.severity;
                break;
            case '3.0':
                cvss30Score = metric.score;
                cvss30Severity = metric.severity;
                break;
            case '3.1':
                cvss31Score = metric.score;
                cvss31Severity = metric.severity;
                break;
        }
    }

    return {
        id,
        description,
        published,
        lastModified,
        vulnStatus,
        // Primary score for backward compatibility
        cvssVersion: primaryVersion,
        score: primaryScore,
        severity: primarySeverity,
        vector: primaryVector,
        // Version-specific scores
        cvss2Score,
        cvss2Severity,
        cvss30Score,
        cvss30Severity,
        cvss31Score,
        cvss31Severity,
        // All metrics for database storage
        allMetrics,
        kev: kevSet ? kevSet.has(id) : false,
        // References with tags (full objects)
        references: refs,
        // Simple URL list for FTS indexing
        referenceUrls: refUrls,
        configurations,
        // New fields
        title,
        sourceAdvisory,
        cwes,
        capecs,
        ssvc,
        workarounds,
        solutions
    };
}

// --- Database Operations (async) ---

// Bulk mode helpers
async function setBulkLoadMode(enabled, dbRef) {
    bulkLoadMode = enabled;
    if (enabled) {
        console.log('[Bulk Mode] Enabled - FTS deferred, alerts skipped');
    } else {
        console.log('[Bulk Mode] Disabled');
    }
}

// Rebuild DuckDB FTS index from cves table (called after bulk load)
async function rebuildFtsIndex(logger = null) {
    const log = logger || { info: console.log.bind(console), warn: console.warn.bind(console) };
    const dbRef = await ensureDb();

    // Use the db.js rebuildFtsIndex helper which handles DuckDB FTS
    await dbRebuildFtsIndex();

    if (log.info.constructor.name === 'AsyncFunction') {
        await log.info('FTS index rebuilt using DuckDB FTS extension');
    } else {
        log.info('FTS index rebuilt using DuckDB FTS extension');
    }
}

let activeWatchlists = [];
async function refreshWatchlists(dbRef) {
    const rows = await dbRef.all('SELECT * FROM watchlists WHERE enabled = 1');
    activeWatchlists = rows.map(w => ({
        ...w,
        query: JSON.parse(w.query_json)
    }));
}

// Async batch processing function
async function processBatch(batch, dbRef) {
    let changed = 0;

    await dbRef.transaction(async () => {
        for (const item of batch) {
            const hash = computeHash(item);
            const existing = await dbRef.get('SELECT normalized_hash, json FROM cves WHERE id = $1', item.id);

            if (existing && existing.normalized_hash === hash) continue;

            if (existing && !bulkLoadMode) {
                // Skip change tracking in bulk mode for speed
                const diff = getDiff(JSON.parse(existing.json), item);
                // Use CVE's dateUpdated from source data, not system time
                const changeDate = item.lastModified || item.published || getTimestamp();
                if (Object.keys(diff).length > 0) {
                    await dbRef.run(
                        'INSERT INTO cve_changes (cve_id, change_date, diff_json) VALUES ($1, $2, $3)',
                        item.id, changeDate, JSON.stringify(diff)
                    );
                }
            }

            await dbRef.run(`
              INSERT INTO cves (id, description, published, last_modified, vuln_status, normalized_hash, json, title, source_advisory)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
              ON CONFLICT(id) DO UPDATE SET
                description = excluded.description, last_modified = excluded.last_modified,
                vuln_status = excluded.vuln_status, normalized_hash = excluded.normalized_hash, json = excluded.json,
                title = excluded.title, source_advisory = excluded.source_advisory
            `, item.id, item.description, item.published, item.lastModified, item.vulnStatus,
               hash, JSON.stringify(item), item.title || null, item.sourceAdvisory || null);

            await dbRef.run('DELETE FROM metrics WHERE cve_id = $1', item.id);
            // Insert all CVSS metrics instead of just the primary one
            if (item.allMetrics && item.allMetrics.length > 0) {
                for (const metric of item.allMetrics) {
                    await dbRef.run(
                        'INSERT INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES ($1, $2, $3, $4, $5)',
                        item.id, metric.version, metric.score, metric.severity, metric.vector
                    );
                }
            } else if (item.score !== null) {
                // Fallback to original logic for backward compatibility
                await dbRef.run(
                    'INSERT INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES ($1, $2, $3, $4, $5)',
                    item.id, item.cvssVersion, item.score, item.severity, item.vector
                );
            }

            // Handle references - can be either old format (string[]) or new format ({url, tags}[])
            await dbRef.run('DELETE FROM cve_references WHERE cve_id = $1', item.id);
            const refUrls = [];
            for (const ref of item.references) {
                if (typeof ref === 'string') {
                    // Old format - just URL
                    await dbRef.run('INSERT INTO cve_references (cve_id, url, tags) VALUES ($1, $2, $3)', item.id, ref, null);
                    refUrls.push(ref);
                } else {
                    // New format - {url, tags}
                    await dbRef.run(
                        'INSERT INTO cve_references (cve_id, url, tags) VALUES ($1, $2, $3)',
                        item.id, ref.url, ref.tags?.length ? JSON.stringify(ref.tags) : null
                    );
                    refUrls.push(ref.url);
                }
            }

            await dbRef.run('DELETE FROM configs WHERE cve_id = $1', item.id);
            if (item.configurations.length > 0) {
                await dbRef.run('INSERT INTO configs (cve_id, nodes) VALUES ($1, $2)', item.id, JSON.stringify(item.configurations));
            }

            // Insert denormalized vendor/product data for fast queries
            await dbRef.run('DELETE FROM cve_products WHERE cve_id = $1', item.id);
            if (item.configurations.length > 0) {
                const seenProducts = new Set();
                for (const config of item.configurations) {
                    const vendor = config.vendor || 'n/a';
                    const product = config.product || 'n/a';
                    const key = `${vendor}|${product}`;
                    if (!seenProducts.has(key) && vendor !== 'n/a' && product !== 'n/a') {
                        seenProducts.add(key);
                        await dbRef.run(
                            'INSERT INTO cve_products (cve_id, vendor, product) VALUES ($1, $2, $3)',
                            item.id, vendor, product
                        );
                    }
                }
            }

            // Insert CWE classifications
            await dbRef.run('DELETE FROM cve_cwes WHERE cve_id = $1', item.id);
            if (item.cwes?.length > 0) {
                for (const cwe of item.cwes) {
                    await dbRef.run(
                        'INSERT INTO cve_cwes (cve_id, cwe_id, description) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
                        item.id, cwe.cweId, cwe.description
                    );
                }
            }

            // Insert CAPEC attack patterns
            await dbRef.run('DELETE FROM cve_capec WHERE cve_id = $1', item.id);
            if (item.capecs?.length > 0) {
                for (const capec of item.capecs) {
                    await dbRef.run(
                        'INSERT INTO cve_capec (cve_id, capec_id, description) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
                        item.id, capec.capecId, capec.description
                    );
                }
            }

            // Insert SSVC scores
            await dbRef.run('DELETE FROM cve_ssvc WHERE cve_id = $1', item.id);
            if (item.ssvc?.length > 0) {
                for (const s of item.ssvc) {
                    await dbRef.run(
                        'INSERT INTO cve_ssvc (cve_id, exploitation, automatable, technical_impact, provider) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING',
                        item.id, s.exploitation, s.automatable, s.technicalImpact, s.provider
                    );
                }
            }

            // Insert workarounds
            await dbRef.run('DELETE FROM cve_workarounds WHERE cve_id = $1', item.id);
            if (item.workarounds?.length > 0) {
                for (const w of item.workarounds) {
                    await dbRef.run(
                        'INSERT INTO cve_workarounds (cve_id, workaround_text, language) VALUES ($1, $2, $3)',
                        item.id, w.text, w.language
                    );
                }
            }

            // Insert solutions
            await dbRef.run('DELETE FROM cve_solutions WHERE cve_id = $1', item.id);
            if (item.solutions?.length > 0) {
                for (const s of item.solutions) {
                    await dbRef.run(
                        'INSERT INTO cve_solutions (cve_id, solution_text, language) VALUES ($1, $2, $3)',
                        item.id, s.text, s.language
                    );
                }
            }

            // Skip alert generation in bulk mode (initial loads shouldn't trigger alerts)
            if (!bulkLoadMode) {
                for (const wl of activeWatchlists) {
                    try {
                        if (matchesQuery(item, wl.query)) {
                            // Check for existing unread alert to prevent duplicates
                            const existingAlert = await dbRef.get(
                                'SELECT id FROM alerts WHERE cve_id = $1 AND watchlist_id = $2 AND read = 0',
                                item.id, wl.id
                            );
                            if (!existingAlert) {
                                const type = existing ? 'UPDATED_MATCH' : 'NEW_MATCH';
                                await dbRef.run(
                                    'INSERT INTO alerts (cve_id, watchlist_id, watchlist_name, type, created_at) VALUES ($1, $2, $3, $4, $5)',
                                    item.id, wl.id, wl.name, type, getTimestamp()
                                );
                                // Update watchlist match count
                                await dbRef.run('UPDATE watchlists SET match_count = match_count + 1 WHERE id = $1', wl.id);
                                console.log(`[Alert] Generated ${type} alert for ${item.id} matching watchlist "${wl.name}"`);
                            }
                        }
                    } catch (alertError) {
                        console.error(`[Alert] Failed to generate alert for ${item.id} on watchlist "${wl.name}":`, alertError.message);
                        // Continue processing other watchlists even if one fails
                    }
                }
            }

            changed++;
        }
    });

    return changed;
}

// --- Main Ingest Logic ---

// Progress update frequency (more frequent than BATCH_SIZE for responsive UI)
const PROGRESS_UPDATE_INTERVAL = 100;

async function runIngest(jobId, useBulkMode = false) {
    const dbRef = await ensureDb();
    const logger = new JobLogger(jobId, dbRef);
    let totalProcessed = 0;
    let stats = { added: 0, updated: 0, unchanged: 0, parseErrors: 0 };
    let totalFiles = 0;
    let lastHeartbeat = Date.now();

    // Enable bulk mode if requested (skips FTS updates, alerts, change tracking)
    if (useBulkMode) {
        await setBulkLoadMode(true, dbRef);
        await logger.info('Bulk load mode enabled for faster import');
    }

    // Cancellation check helper
    const checkCancelled = async () => {
        const result = await dbRef.get('SELECT cancel_requested FROM job_runs WHERE id = $1', jobId);
        return result?.cancel_requested === 1;
    };

    // Update progress helper
    const updateProgress = async (phase, processed = totalProcessed) => {
        const now = Date.now();
        // Always update heartbeat, but throttle full progress updates
        if (now - lastHeartbeat > 5000 || processed % PROGRESS_UPDATE_INTERVAL === 0) {
            const percent = totalFiles > 0 ? Math.round((processed / totalFiles) * 100) : 0;
            await dbRef.run(`
                UPDATE job_runs SET
                  progress_percent = $1, items_processed = $2, items_added = $3, items_updated = $4,
                  items_unchanged = $5, current_phase = $6, last_heartbeat = $7, total_files = $8
                WHERE id = $9
            `, percent, processed, stats.added, stats.updated, stats.unchanged, phase, getTimestamp(), totalFiles, jobId);
            lastHeartbeat = now;
        }
    };

    try {
        await logger.info('Starting ingestion job');
        await updateProgress('INITIALIZING');

        await refreshWatchlists(dbRef);
        await logger.info('Loaded active watchlists', { count: activeWatchlists.length });

        // Fetch CISA KEV catalog for marking known exploited vulnerabilities
        const kevSet = await fetchKevCatalog(logger);

        // Check cancellation before git operations
        if (await checkCancelled()) {
            await logger.info('Job cancelled before repository preparation');
            await dbRef.run('UPDATE job_runs SET end_time = $1, status = $2, items_processed = $3, error = $4 WHERE id = $5',
                getTimestamp(), 'CANCELLED', 0, 'Cancelled by user', jobId);
            return;
        }

        await updateProgress('PREPARING_REPO');
        const repoResult = await prepareRepo(logger, checkCancelled, dbRef);

        if (repoResult.cancelled) {
            await logger.info('Job cancelled during repository preparation');
            await dbRef.run('UPDATE job_runs SET end_time = $1, status = $2, items_processed = $3, error = $4 WHERE id = $5',
                getTimestamp(), 'CANCELLED', 0, 'Cancelled by user', jobId);
            return;
        }

        const { mode, oldHash, newHash, noChanges } = repoResult;

        if (noChanges) {
            await logger.info('No changes to process');
            await dbRef.run('UPDATE job_runs SET end_time = $1, status = $2, items_processed = $3, error = $4 WHERE id = $5',
                getTimestamp(), 'COMPLETED', 0, 'No updates found', jobId);
            return;
        }

        // Determine file source
        await updateProgress('SCANNING_FILES');
        let fileSource;
        if (mode === 'full') {
            fileSource = walk(path.join(REPO_DIR, 'cves'));
            // Count total files for progress (this is expensive but worth it for UX)
            const allFiles = [...walk(path.join(REPO_DIR, 'cves'))];
            totalFiles = allFiles.length;
            fileSource = allFiles; // Use the array we just created
            await logger.info('Full scan mode', { totalFiles });
        } else {
            fileSource = getChangedFiles(oldHash, newHash, logger);
            if (!fileSource) {
                // Fallback to full scan
                await logger.warn('Diff failed, falling back to full scan');
                const allFiles = [...walk(path.join(REPO_DIR, 'cves'))];
                totalFiles = allFiles.length;
                fileSource = allFiles;
            } else {
                totalFiles = fileSource.length;
            }
        }

        if (!fileSource || totalFiles === 0) {
            await logger.info('No files to process');
            await dbRef.run('UPDATE job_runs SET end_time = $1, status = $2, items_processed = $3, error = $4 WHERE id = $5',
                getTimestamp(), 'COMPLETED', 0, 'No files to process', jobId);
            return;
        }

        await logger.info('Starting file processing', { mode, totalFiles, parallelReads: CONCURRENCY });
        await updateProgress('PROCESSING');

        let batch = [];
        let filesRead = 0;

        const processFile = async (filePath) => {
            try {
                const content = await fs.promises.readFile(filePath, 'utf8');
                return normalizeCve5(JSON.parse(content), kevSet);
            } catch (err) {
                // Track failures but don't log each one individually (too noisy)
                stats.parseErrors++;
                // Log unexpected errors (not just malformed JSON or missing files)
                if (err.code !== 'ENOENT' && !err.message?.includes('Unexpected token')) {
                    console.warn(`[Ingest] Unexpected error processing ${path.basename(filePath)}: ${err.message}`);
                }
                return null;
            }
        };

        // Collect files into read batches for parallel I/O
        let readBatch = [];

        // Process files with parallel reads and cancellation checks
        for (const file of fileSource) {
            readBatch.push(file);

            // When we have enough files for parallel read, process them
            if (readBatch.length >= CONCURRENCY) {
                // Check cancellation before parallel read
                if (await checkCancelled()) {
                    await logger.info('Job cancelled during file processing', { processed: totalProcessed });
                    await dbRef.run('UPDATE job_runs SET end_time = $1, status = $2, items_processed = $3, error = $4 WHERE id = $5',
                        getTimestamp(), 'CANCELLED', totalProcessed, 'Cancelled by user', jobId);
                    return;
                }

                // Parallel file reads
                const results = await Promise.all(readBatch.map(f => processFile(f)));
                filesRead += readBatch.length;
                readBatch = [];

                // Process results
                for (const normalized of results) {
                    if (normalized) {
                        // Track if this is a new or updated CVE
                        const existing = await dbRef.get('SELECT normalized_hash FROM cves WHERE id = $1', normalized.id);
                        if (!existing) {
                            stats.added++;
                        } else if (existing.normalized_hash !== computeHash(normalized)) {
                            stats.updated++;
                        } else {
                            stats.unchanged++;
                        }

                        batch.push(normalized);
                    }
                }

                // Flush batch if large enough
                if (batch.length >= BATCH_SIZE) {
                    await refreshWatchlists(dbRef);
                    await processBatch(batch, dbRef);
                    totalProcessed += batch.length;
                    batch = [];
                    await updateProgress('PROCESSING', totalProcessed);
                    await logger.info('Batch processed', { totalProcessed, added: stats.added, updated: stats.updated });

                    // Yield to event loop so API requests can be processed
                    await yieldToEventLoop();
                }

                // Update progress for UI responsiveness
                if (filesRead % PROGRESS_UPDATE_INTERVAL === 0) {
                    await updateProgress('PROCESSING', totalProcessed);
                }
            }
        }

        // Process remaining read batch
        if (readBatch.length > 0) {
            const results = await Promise.all(readBatch.map(f => processFile(f)));
            filesRead += readBatch.length;

            for (const normalized of results) {
                if (normalized) {
                    const existing = await dbRef.get('SELECT normalized_hash FROM cves WHERE id = $1', normalized.id);
                    if (!existing) {
                        stats.added++;
                    } else if (existing.normalized_hash !== computeHash(normalized)) {
                        stats.updated++;
                    } else {
                        stats.unchanged++;
                    }
                    batch.push(normalized);
                }
            }
        }

        // Process remaining batch
        if (batch.length > 0) {
            await processBatch(batch, dbRef);
            totalProcessed += batch.length;
            await yieldToEventLoop();
        }

        // Final update
        await dbRef.run(
            "INSERT INTO system_metadata (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            'cvelist_commit', newHash
        );

        // Rebuild FTS index if we were in bulk mode
        if (useBulkMode) {
            await updateProgress('REBUILDING_FTS', totalProcessed);
            await logger.info('Rebuilding full-text search index...');
            await rebuildFtsIndex(logger);
            await setBulkLoadMode(false, dbRef);
        }

        await updateProgress('COMPLETED', totalProcessed);

        await logger.info('Ingestion completed successfully', {
            totalProcessed,
            added: stats.added,
            updated: stats.updated,
            unchanged: stats.unchanged,
            parseErrors: stats.parseErrors
        });

        await dbRef.run('UPDATE job_runs SET end_time = $1, status = $2, items_processed = $3, error = $4 WHERE id = $5',
            getTimestamp(), 'COMPLETED', totalProcessed, null, jobId);

    } catch (err) {
        // Ensure bulk mode is disabled even on error
        if (useBulkMode) {
            await setBulkLoadMode(false, dbRef);
        }
        await logger.error('Ingestion failed', { error: err.message, stack: err.stack });
        await dbRef.run('UPDATE job_runs SET end_time = $1, status = $2, items_processed = $3, error = $4 WHERE id = $5',
            getTimestamp(), 'FAILED', totalProcessed, err.message, jobId);
    }
}

export async function run() {
    const dbRef = await ensureDb();
    const timestamp = getTimestamp();
    const result = await dbRef.get(
        "INSERT INTO job_runs (start_time, status, items_processed, last_heartbeat) VALUES ($1, 'RUNNING', 0, $2) RETURNING id",
        timestamp, timestamp
    );
    const jobId = result.id;
    runIngest(jobId, false).catch(err => console.error('Ingest error:', err));
    return jobId;
}

// Run ingestion in bulk mode (faster for initial loads / full rescans)
// Skips FTS per-row updates (rebuilds at end), skips alerts, larger batches
export async function runBulk() {
    const dbRef = await ensureDb();
    const timestamp = getTimestamp();
    const result = await dbRef.get(
        "INSERT INTO job_runs (start_time, status, items_processed, last_heartbeat) VALUES ($1, 'RUNNING', 0, $2) RETURNING id",
        timestamp, timestamp
    );
    const jobId = result.id;
    runIngest(jobId, true).catch(err => console.error('Bulk ingest error:', err));
    return jobId;
}

// Cancel a running job
export async function cancelJob(jobId) {
    const dbRef = await ensureDb();
    await dbRef.run('UPDATE job_runs SET cancel_requested = 1 WHERE id = $1', jobId);
}

// Get job logs
export async function getJobLogs(jobId) {
    const dbRef = await ensureDb();
    return await dbRef.all('SELECT * FROM job_logs WHERE job_id = $1 ORDER BY id ASC', jobId);
}

export async function getJobLogsSince(jobId, sinceId) {
    const dbRef = await ensureDb();
    return await dbRef.all('SELECT * FROM job_logs WHERE job_id = $1 AND id > $2 ORDER BY id ASC', jobId, sinceId);
}

// Export helper functions for testing and external use
export {
    computeHash,
    getDiff,
    ensureDir,
    getTimestamp,
    walk,
    gitSpawn,
    getChangedFiles,
    prepareRepo,
    processBatch,
    refreshWatchlists,
    JobLogger,
    setBulkLoadMode,
    rebuildFtsIndex
};
