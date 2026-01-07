import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import db from '../db.js';
import { matchesQuery } from '../matcher.js';

// --- Configuration ---
const DATA_DIR = path.resolve(process.cwd(), 'data');
const REPO_DIR = path.join(DATA_DIR, 'cvelistV5');
const REPO_URL = 'https://github.com/CVEProject/cvelistV5';
const BATCH_SIZE = 2000; // Increased for better SQLite throughput
const CONCURRENCY = 10; // Parallel file reading/parsing

// --- Helpers ---
const getTimestamp = () => new Date().toISOString();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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
    constructor(jobId) {
        this.jobId = jobId;
    }

    log(level, message, metadata = null) {
        const timestamp = getTimestamp();
        const metadataJson = metadata ? JSON.stringify(metadata) : null;

        // Persist to database (deferred import to avoid circular dependency)
        try {
            statements.insertJobLog.run(this.jobId, timestamp, level, message, metadataJson);
        } catch {
            // Statements may not be ready yet during early init
            console.log(`[Job ${this.jobId}] [${level}] ${message}`);
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
            console.log(prefix, message, metadata ? JSON.stringify(metadata) : '');
        }
    }

    info(message, metadata = null) {
        this.log('INFO', message, metadata);
    }

    warn(message, metadata = null) {
        this.log('WARN', message, metadata);
    }

    error(message, metadata = null) {
        this.log('ERROR', message, metadata);
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
                logger.error(`Git operation failed after ${maxRetries} attempts`, { args: args.join(' '), error: err.message });
                throw err;
            }
            const delay = 5000 * attempt; // Exponential backoff
            logger.warn(`Git operation failed, retrying in ${delay}ms`, { attempt, maxRetries, error: err.message });
            await sleep(delay);
        }
    }
}

async function prepareRepo(logger, checkCancelled) {
    ensureDir(DATA_DIR);

    if (!fs.existsSync(path.join(REPO_DIR, '.git'))) {
        logger.info('Cloning cvelistV5 repository (this may take several minutes)...');

        // Check cancellation before long operation
        if (checkCancelled()) return { cancelled: true };

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
        logger.info('Repository cloned successfully', { commit: newHash.substring(0, 8) });
        return { mode: 'full', oldHash: null, newHash };
    } else {
        logger.info('Pulling updates from repository...');
        const oldHash = gitSpawn(['rev-parse', 'HEAD']);

        // Check cancellation before long operation
        if (checkCancelled()) return { cancelled: true };

        const pullResult = spawnSync('git', ['pull'], {
            cwd: REPO_DIR,
            encoding: 'utf8',
            timeout: GIT_PULL_TIMEOUT,
            maxBuffer: 50 * 1024 * 1024
        });

        if (pullResult.error) {
            if (pullResult.error.code === 'ETIMEDOUT') {
                logger.warn(`Git pull timed out after ${GIT_PULL_TIMEOUT / 1000}s, using local data`);
            } else {
                logger.warn('Git pull failed, using local data', { error: pullResult.error.message });
            }
        } else if (pullResult.status !== 0) {
            logger.warn('Git pull failed, using local data', { exitCode: pullResult.status });
        }

        const newHash = gitSpawn(['rev-parse', 'HEAD']);

        if (oldHash === newHash) {
            // Even if git hasn't changed, check if database is properly populated
            let count = 0;
            try {
                const result = db.prepare('SELECT count(*) as c FROM cves').get();
                count = result ? result.c : 0;
            } catch (e) {
                logger.warn('Database query failed, forcing full scan', { error: e.message });
                return { mode: 'full', oldHash, newHash };
            }

            // If database is empty or suspiciously small, force full scan
            if (count === 0) {
                logger.info('Database is empty, forcing full scan');
                return { mode: 'full', oldHash, newHash };
            }

            // Check if we have the stored commit hash to compare against
            let storedHash = null;
            try {
                const result = db.prepare("SELECT value FROM system_metadata WHERE key = 'cvelist_commit'").get();
                storedHash = result ? result.value : null;
            } catch (e) {
                // Table might not exist yet
            }

            // If we don't have a stored hash, we can't be sure database is current
            if (!storedHash) {
                logger.info('No stored commit hash found, forcing full scan to ensure database is current');
                return { mode: 'full', oldHash, newHash };
            }

            // Only skip if we have a reasonable number of CVEs (>100,000 is full dataset)
            // AND git truly hasn't changed AND we have a stored hash matching current
            if (count < 100000) {
                logger.info('Database has insufficient CVEs, forcing full scan', { count, expected: '~250k' });
                return { mode: 'full', oldHash, newHash };
            }

            logger.info('No git changes and database is current, skipping ingestion', { cveCount: count });
            return { mode: 'incremental', oldHash, newHash, noChanges: true };
        }

        // Git pulled new commits - check if we have a stored hash to know where we left off
        let storedHash = null;
        let dbCount = 0;
        try {
            const result = db.prepare("SELECT value FROM system_metadata WHERE key = 'cvelist_commit'").get();
            storedHash = result ? result.value : null;

            const countResult = db.prepare('SELECT count(*) as c FROM cves').get();
            dbCount = countResult ? countResult.c : 0;
        } catch (e) {
            logger.warn('Database check failed, forcing full scan', { error: e.message });
            return { mode: 'full', oldHash, newHash };
        }

        // If no stored hash, we don't know where we left off - must do full scan
        if (!storedHash) {
            logger.info('No stored commit hash found after git pull, forcing full scan to catch up');
            return { mode: 'full', oldHash, newHash };
        }

        // If database is suspiciously small, do full scan to ensure completeness
        if (dbCount < 100000) {
            logger.info('Database has insufficient CVEs after git pull, forcing full scan', { count: dbCount, expected: '~250k' });
            return { mode: 'full', oldHash, newHash };
        }

        // We have a stored hash and good CVE count - use incremental diff from stored hash to new hash
        logger.info('Incremental update mode', { fromCommit: storedHash.substring(0, 8), toCommit: newHash.substring(0, 8) });
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
        log.info('Found changed files', { count: files.length });
        return files;
    } catch (e) {
        log.warn('Failed to calculate diff, falling back to full scan', { error: e.message });
        return null; // Signals full scan needed
    }
}

// --- CVE JSON 5.0 Normalization ---
export function normalizeCve5(raw) {
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

    const refs = (cna.references || []).map(r => r.url).sort();
    const configurations = [];
    if (cna.affected) {
        for (const aff of cna.affected) {
            if (aff.product) configurations.push({ product: aff.product, vendor: aff.vendor });
        }
    }

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
        kev: false, 
        references: refs, 
        configurations 
    };
}

// --- Database Operations ---
const statements = {
    // Job management
    insertJob: db.prepare(`
      INSERT INTO job_runs (start_time, status, items_processed, last_heartbeat)
      VALUES (?, 'RUNNING', 0, ?) RETURNING id
    `),
    updateJob: db.prepare(`
      UPDATE job_runs SET end_time = ?, status = ?, items_processed = ?, error = ? WHERE id = ?
    `),
    updateJobProgress: db.prepare(`
      UPDATE job_runs SET
        progress_percent = ?, items_processed = ?, items_added = ?, items_updated = ?,
        items_unchanged = ?, current_phase = ?, last_heartbeat = ?, total_files = ?
      WHERE id = ?
    `),
    checkCancelRequested: db.prepare('SELECT cancel_requested FROM job_runs WHERE id = ?'),
    requestJobCancel: db.prepare('UPDATE job_runs SET cancel_requested = 1 WHERE id = ?'),
    updateJobHeartbeat: db.prepare('UPDATE job_runs SET last_heartbeat = ? WHERE id = ?'),

    // Job logging
    insertJobLog: db.prepare(`
      INSERT INTO job_logs (job_id, timestamp, level, message, metadata)
      VALUES (?, ?, ?, ?, ?)
    `),
    getJobLogs: db.prepare('SELECT * FROM job_logs WHERE job_id = ? ORDER BY id ASC'),
    getJobLogsSince: db.prepare('SELECT * FROM job_logs WHERE job_id = ? AND id > ? ORDER BY id ASC'),

    // CVE operations
    getCveHash: db.prepare('SELECT normalized_hash, json FROM cves WHERE id = ?'),
    upsertCve: db.prepare(`
      INSERT INTO cves (id, description, published, last_modified, vuln_status, normalized_hash, json)
      VALUES (@id, @description, @published, @lastModified, @vulnStatus, @hash, @json)
      ON CONFLICT(id) DO UPDATE SET
        description = excluded.description, last_modified = excluded.last_modified,
        vuln_status = excluded.vuln_status, normalized_hash = excluded.normalized_hash, json = excluded.json
    `),
    deleteMetrics: db.prepare('DELETE FROM metrics WHERE cve_id = ?'),
    insertMetric: db.prepare('INSERT INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES (?, ?, ?, ?, ?)'),
    deleteRefs: db.prepare('DELETE FROM cve_references WHERE cve_id = ?'),
    insertRef: db.prepare('INSERT INTO cve_references (cve_id, url) VALUES (?, ?)'),
    deleteConfigs: db.prepare('DELETE FROM configs WHERE cve_id = ?'),
    insertConfig: db.prepare('INSERT INTO configs (cve_id, nodes) VALUES (?, ?)'),
    deleteFts: db.prepare('DELETE FROM cves_fts WHERE id = ?'),
    insertFts: db.prepare('INSERT INTO cves_fts (id, description, refs) VALUES (?, ?, ?)'),
    insertChange: db.prepare('INSERT INTO cve_changes (cve_id, change_date, diff_json) VALUES (?, ?, ?)'),
    setMeta: db.prepare("INSERT INTO system_metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"),
    getActiveWatchlists: db.prepare('SELECT * FROM watchlists WHERE enabled = 1'),
    insertAlert: db.prepare(`
      INSERT INTO alerts (cve_id, watchlist_id, watchlist_name, type, created_at)
      VALUES (?, ?, ?, ?, ?)
    `),
    checkExistingAlert: db.prepare('SELECT id FROM alerts WHERE cve_id = ? AND watchlist_id = ? AND read = 0'),
    updateWatchlistMatchCount: db.prepare('UPDATE watchlists SET match_count = match_count + 1 WHERE id = ?')
};

let activeWatchlists = [];
function refreshWatchlists() {
    activeWatchlists = statements.getActiveWatchlists.all().map(w => ({
        ...w,
        query: JSON.parse(w.query_json)
    }));
}

// Optimized transaction for bulk processing
const processBatch = db.transaction((batch) => {
    let changed = 0;
    for (const item of batch) {
        const hash = computeHash(item);
        const existing = statements.getCveHash.get(item.id);

        if (existing && existing.normalized_hash === hash) continue;

        if (existing) {
            const diff = getDiff(JSON.parse(existing.json), item);
            if (Object.keys(diff).length > 0) statements.insertChange.run(item.id, getTimestamp(), JSON.stringify(diff));
        }

        statements.upsertCve.run({
            id: item.id, description: item.description, published: item.published,
            lastModified: item.lastModified, vulnStatus: item.vulnStatus, hash, json: JSON.stringify(item)
        });

        statements.deleteMetrics.run(item.id);
        // Insert all CVSS metrics instead of just the primary one
        if (item.allMetrics && item.allMetrics.length > 0) {
            for (const metric of item.allMetrics) {
                statements.insertMetric.run(item.id, metric.version, metric.score, metric.severity, metric.vector);
            }
        } else if (item.score !== null) {
            // Fallback to original logic for backward compatibility
            statements.insertMetric.run(item.id, item.cvssVersion, item.score, item.severity, item.vector);
        }

        statements.deleteRefs.run(item.id);
        for (const url of item.references) statements.insertRef.run(item.id, url);

        statements.deleteConfigs.run(item.id);
        if (item.configurations.length > 0) statements.insertConfig.run(item.id, JSON.stringify(item.configurations));

        statements.deleteFts.run(item.id);
        statements.insertFts.run(item.id, item.description, item.references.join(' '));

        // Alert Generation
        for (const wl of activeWatchlists) {
            try {
                if (matchesQuery(item, wl.query)) {
                    // Check for existing unread alert to prevent duplicates
                    const existingAlert = statements.checkExistingAlert.get(item.id, wl.id);
                    if (!existingAlert) {
                        const type = existing ? 'UPDATED_MATCH' : 'NEW_MATCH';
                        statements.insertAlert.run(item.id, wl.id, wl.name, type, getTimestamp());
                        // Update watchlist match count
                        statements.updateWatchlistMatchCount.run(wl.id);
                        console.log(`[Alert] Generated ${type} alert for ${item.id} matching watchlist "${wl.name}"`);
                    }
                }
            } catch (alertError) {
                console.error(`[Alert] Failed to generate alert for ${item.id} on watchlist "${wl.name}":`, alertError.message);
                // Continue processing other watchlists even if one fails
            }
        }

        changed++;
    }
    return changed;
});

// --- Main Ingest Logic ---

// Progress update frequency (more frequent than BATCH_SIZE for responsive UI)
const PROGRESS_UPDATE_INTERVAL = 100;

async function runIngest(jobId) {
    const logger = new JobLogger(jobId);
    let totalProcessed = 0;
    let stats = { added: 0, updated: 0, unchanged: 0 };
    let totalFiles = 0;
    let lastHeartbeat = Date.now();

    // Cancellation check helper
    const checkCancelled = () => {
        const result = statements.checkCancelRequested.get(jobId);
        return result?.cancel_requested === 1;
    };

    // Update progress helper
    const updateProgress = (phase, processed = totalProcessed) => {
        const now = Date.now();
        // Always update heartbeat, but throttle full progress updates
        if (now - lastHeartbeat > 5000 || processed % PROGRESS_UPDATE_INTERVAL === 0) {
            const percent = totalFiles > 0 ? Math.round((processed / totalFiles) * 100) : 0;
            statements.updateJobProgress.run(
                percent, processed, stats.added, stats.updated, stats.unchanged,
                phase, getTimestamp(), totalFiles, jobId
            );
            lastHeartbeat = now;
        }
    };

    try {
        logger.info('Starting ingestion job');
        updateProgress('INITIALIZING');

        refreshWatchlists();
        logger.info('Loaded active watchlists', { count: activeWatchlists.length });

        // Check cancellation before git operations
        if (checkCancelled()) {
            logger.info('Job cancelled before repository preparation');
            statements.updateJob.run(getTimestamp(), 'CANCELLED', 0, 'Cancelled by user', jobId);
            return;
        }

        updateProgress('PREPARING_REPO');
        const repoResult = await prepareRepo(logger, checkCancelled);

        if (repoResult.cancelled) {
            logger.info('Job cancelled during repository preparation');
            statements.updateJob.run(getTimestamp(), 'CANCELLED', 0, 'Cancelled by user', jobId);
            return;
        }

        const { mode, oldHash, newHash, noChanges } = repoResult;

        if (noChanges) {
            logger.info('No changes to process');
            statements.updateJob.run(getTimestamp(), 'COMPLETED', 0, 'No updates found', jobId);
            return;
        }

        // Determine file source
        updateProgress('SCANNING_FILES');
        let fileSource;
        if (mode === 'full') {
            fileSource = walk(path.join(REPO_DIR, 'cves'));
            // Count total files for progress (this is expensive but worth it for UX)
            const allFiles = [...walk(path.join(REPO_DIR, 'cves'))];
            totalFiles = allFiles.length;
            fileSource = allFiles; // Use the array we just created
            logger.info('Full scan mode', { totalFiles });
        } else {
            fileSource = getChangedFiles(oldHash, newHash, logger);
            if (!fileSource) {
                // Fallback to full scan
                logger.warn('Diff failed, falling back to full scan');
                const allFiles = [...walk(path.join(REPO_DIR, 'cves'))];
                totalFiles = allFiles.length;
                fileSource = allFiles;
            } else {
                totalFiles = fileSource.length;
            }
        }

        if (!fileSource || totalFiles === 0) {
            logger.info('No files to process');
            statements.updateJob.run(getTimestamp(), 'COMPLETED', 0, 'No files to process', jobId);
            return;
        }

        logger.info('Starting file processing', { mode, totalFiles });
        updateProgress('PROCESSING');

        let batch = [];
        let filesRead = 0;

        const processFile = async (filePath) => {
            try {
                const content = await fs.promises.readFile(filePath, 'utf8');
                return normalizeCve5(JSON.parse(content));
            } catch (err) {
                // Silent failure for parse errors (too noisy otherwise)
                return null;
            }
        };

        // Process files with cancellation checks and progress updates
        for (const file of fileSource) {
            // Check cancellation every 100 files
            if (filesRead % 100 === 0 && checkCancelled()) {
                logger.info('Job cancelled during file processing', { processed: totalProcessed });
                statements.updateJob.run(getTimestamp(), 'CANCELLED', totalProcessed, 'Cancelled by user', jobId);
                return;
            }

            const normalized = await processFile(file);
            filesRead++;

            if (normalized) {
                // Track if this is a new or updated CVE
                const existing = statements.getCveHash.get(normalized.id);
                if (!existing) {
                    stats.added++;
                } else if (existing.normalized_hash !== computeHash(normalized)) {
                    stats.updated++;
                } else {
                    stats.unchanged++;
                }

                batch.push(normalized);
            }

            if (batch.length >= BATCH_SIZE) {
                refreshWatchlists();
                processBatch(batch);
                totalProcessed += batch.length;
                batch = [];
                updateProgress('PROCESSING', totalProcessed);
                logger.info('Batch processed', { totalProcessed, added: stats.added, updated: stats.updated });
            }

            // Update progress for UI responsiveness
            if (filesRead % PROGRESS_UPDATE_INTERVAL === 0) {
                updateProgress('PROCESSING', totalProcessed);
            }
        }

        // Process remaining batch
        if (batch.length > 0) {
            processBatch(batch);
            totalProcessed += batch.length;
        }

        // Final update
        statements.setMeta.run('cvelist_commit', newHash);
        updateProgress('COMPLETED', totalProcessed);

        logger.info('Ingestion completed successfully', {
            totalProcessed,
            added: stats.added,
            updated: stats.updated,
            unchanged: stats.unchanged
        });

        statements.updateJob.run(getTimestamp(), 'COMPLETED', totalProcessed, null, jobId);

    } catch (err) {
        logger.error('Ingestion failed', { error: err.message, stack: err.stack });
        statements.updateJob.run(getTimestamp(), 'FAILED', totalProcessed, err.message, jobId);
    }
}

export function run() {
    const timestamp = getTimestamp();
    const jobId = statements.insertJob.get(timestamp, timestamp).id;
    runIngest(jobId).catch(err => console.error('Ingest error:', err));
    return jobId;
}

// Cancel a running job
export function cancelJob(jobId) {
    statements.requestJobCancel.run(jobId);
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
    statements,
    JobLogger
};
