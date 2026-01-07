import fs from 'node:fs';
import path from 'node:path';
import { execSync, spawn } from 'node:child_process';
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
function gitExec(args, cwd = REPO_DIR) {
    try {
        return execSync(`git ${args}`, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch (e) {
        throw new Error(`Git command failed: git ${args}`);
    }
}

async function prepareRepo() {
    ensureDir(DATA_DIR);

    if (!fs.existsSync(path.join(REPO_DIR, '.git'))) {
        console.log('[Ingest] Cloning cvelistV5 (this may take a few minutes)...');
        execSync(`git clone --depth 1 ${REPO_URL} ${REPO_DIR}`, { stdio: 'inherit' });
        return { mode: 'full', oldHash: null, newHash: gitExec('rev-parse HEAD') };
    } else {
        console.log('[Ingest] Pulling updates...');
        const oldHash = gitExec('rev-parse HEAD');
        try {
            execSync('git pull', { cwd: REPO_DIR, stdio: 'inherit' });
        } catch (e) {
            console.warn('[Ingest] Git pull failed, reaching out to current local data.');
        }
        const newHash = gitExec('rev-parse HEAD');

        if (oldHash === newHash) {
            // Even if git hasn't changed, check if database is properly populated
            let count = 0;
            try {
                const result = db.prepare('SELECT count(*) as c FROM cves').get();
                count = result ? result.c : 0;
            } catch (e) {
                console.warn('[Ingest] Database query failed, forcing full scan:', e.message);
                return { mode: 'full', oldHash, newHash };
            }

            // If database is empty or suspiciously small, force full scan
            if (count === 0) {
                console.log('[Ingest] Database is empty, forcing full scan');
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
                console.log('[Ingest] No stored commit hash found, forcing full scan to ensure database is current');
                return { mode: 'full', oldHash, newHash };
            }

            // Only skip if we have a reasonable number of CVEs (>100,000 is full dataset)
            // AND git truly hasn't changed AND we have a stored hash matching current
            if (count < 100000) {
                console.log(`[Ingest] Database has only ${count} CVEs (expected ~250k), forcing full scan`);
                return { mode: 'full', oldHash, newHash };
            }

            console.log(`[Ingest] No git changes and database has ${count} CVEs, skipping`);
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
            console.warn('[Ingest] Database check failed, forcing full scan:', e.message);
            return { mode: 'full', oldHash, newHash };
        }

        // If no stored hash, we don't know where we left off - must do full scan
        if (!storedHash) {
            console.log('[Ingest] No stored commit hash found after git pull, forcing full scan to catch up');
            return { mode: 'full', oldHash, newHash };
        }

        // If database is suspiciously small, do full scan to ensure completeness
        if (dbCount < 100000) {
            console.log(`[Ingest] Database has only ${dbCount} CVEs after git pull (expected ~250k), forcing full scan`);
            return { mode: 'full', oldHash, newHash };
        }

        // We have a stored hash and good CVE count - use incremental diff from stored hash to new hash
        console.log(`[Ingest] Incremental update from ${storedHash.substring(0, 8)} to ${newHash.substring(0, 8)}`);
        return { mode: 'incremental', oldHash: storedHash, newHash };
    }
}

function getChangedFiles(oldHash, newHash) {
    try {
        const diffOutput = gitExec(`diff --name-only ${oldHash} ${newHash}`);
        return diffOutput.split('\n')
            .filter(line => line.startsWith('cves/') && line.endsWith('.json'))
            .map(line => path.join(REPO_DIR, line));
    } catch (e) {
        console.warn('[Ingest] Failed to calc diff, falling back to full scan.', e.message);
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
    insertJob: db.prepare("INSERT INTO job_runs (start_time, status, items_processed) VALUES (?, 'RUNNING', 0) RETURNING id"),
    updateJob: db.prepare("UPDATE job_runs SET end_time = ?, status = ?, items_processed = ?, error = ? WHERE id = ?"),
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

async function runIngest(jobId) {
    let totalProcessed = 0;
    try {
        refreshWatchlists();
        const { mode, oldHash, newHash, noChanges } = await prepareRepo();

        if (noChanges) {
            statements.updateJob.run(getTimestamp(), 'COMPLETED', 0, 'No updates found', jobId);
            return;
        }

        const fileSource = (mode === 'full') ? walk(path.join(REPO_DIR, 'cves')) : getChangedFiles(oldHash, newHash);
        if (!fileSource && mode === 'full') throw new Error("Could not initialize file scan");

        let batch = [];
        console.log(`[Ingest] Starting ingestion (${mode} mode)...`);

        const processFile = async (filePath) => {
            try {
                const content = await fs.promises.readFile(filePath, 'utf8');
                return normalizeCve5(JSON.parse(content));
            } catch (err) {
                // console.warn(`[Ingest] Failed to parse ${filePath}:`, err.message); // Too noisy
                return null;
            }
        };

        if (Array.isArray(fileSource)) {
            // Incremental: simple loop
            for (const file of fileSource) {
                const normalized = await processFile(file);
                if (normalized) batch.push(normalized);
                if (batch.length >= BATCH_SIZE) {
                    refreshWatchlists(); // Ensure we have latest criteria
                    processBatch(batch);
                    totalProcessed += batch.length;
                    batch = [];
                    statements.updateJob.run(null, 'RUNNING', totalProcessed, null, jobId);
                }
            }
        } else {
            // Full: Generator-based with concurrency
            let active = [];
            for (const file of fileSource) {
                active.push(processFile(file).then(n => {
                    if (n) batch.push(n);
                    if (batch.length >= BATCH_SIZE) {
                        refreshWatchlists();
                        processBatch(batch);
                        totalProcessed += batch.length;
                        batch = [];
                        statements.updateJob.run(null, 'RUNNING', totalProcessed, null, jobId);
                        console.log(`[Ingest] Processed ${totalProcessed}...`);
                    }
                }));

                if (active.length >= CONCURRENCY) {
                    await Promise.all(active);
                    active = [];
                }
            }
            await Promise.all(active);
        }

        if (batch.length > 0) {
            processBatch(batch);
            totalProcessed += batch.length;
        }

        statements.setMeta.run('cvelist_commit', newHash);
        statements.updateJob.run(getTimestamp(), 'COMPLETED', totalProcessed, null, jobId);
        console.log(`[Ingest] Completed. ${totalProcessed} items processed.`);

    } catch (err) {
        console.error('[Ingest] Failure:', err);
        statements.updateJob.run(getTimestamp(), 'FAILED', totalProcessed, err.message, jobId);
    }
}

export function run() {
    const jobId = statements.insertJob.get(getTimestamp()).id;
    runIngest(jobId).catch(err => console.error('Ingest error:', err));
    return jobId;
}

// Export helper functions for testing
export {
    computeHash,
    getDiff,
    ensureDir,
    getTimestamp,
    walk,
    gitExec,
    getChangedFiles,
    prepareRepo,
    processBatch,
    refreshWatchlists,
    statements
};
