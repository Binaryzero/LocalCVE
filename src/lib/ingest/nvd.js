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
            const count = db.prepare('SELECT count(*) as c FROM cves').get().c;
            if (count === 0) return { mode: 'full', oldHash, newHash };
            return { mode: 'incremental', oldHash, newHash, noChanges: true };
        }

        return { mode: 'incremental', oldHash, newHash };
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
function normalizeCve5(raw) {
    const meta = raw.cveMetadata || {};
    const cna = raw.containers?.cna || {};

    const id = meta.cveId;
    const vulnStatus = meta.state;
    const published = meta.datePublished ? new Date(meta.datePublished).toISOString() : null;
    const lastModified = meta.dateUpdated ? new Date(meta.dateUpdated).toISOString() : null;

    const descObj = cna.descriptions?.find(d => d.lang === 'en') || cna.descriptions?.[0];
    const description = descObj ? descObj.value : 'No description available';

    let score = null, severity = null, vector = null, cvssVersion = null;
    const metrics = cna.metrics || [];
    for (const m of metrics) {
        if (m.cvssV3_1) {
            score = m.cvssV3_1.baseScore; severity = m.cvssV3_1.baseSeverity;
            vector = m.cvssV3_1.vectorString; cvssVersion = '3.1'; break;
        }
        if (m.cvssV3_0) {
            score = m.cvssV3_0.baseScore; severity = m.cvssV3_0.baseSeverity;
            vector = m.cvssV3_0.vectorString; cvssVersion = '3.0'; break;
        }
    }
    if (!cvssVersion) {
        for (const m of metrics) {
            if (m.cvssV2_0) {
                score = m.cvssV2_0.baseScore;
                severity = m.cvssV2_0.baseSeverity || 'UNKNOWN';
                vector = m.cvssV2_0.vectorString; cvssVersion = '2.0'; break;
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

    return { id, description, published, lastModified, vulnStatus, cvssVersion, score, severity, vector, kev: false, references: refs, configurations };
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
    `)
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
        if (item.score !== null) statements.insertMetric.run(item.id, item.cvssVersion, item.score, item.severity, item.vector);

        statements.deleteRefs.run(item.id);
        for (const url of item.references) statements.insertRef.run(item.id, url);

        statements.deleteConfigs.run(item.id);
        if (item.configurations.length > 0) statements.insertConfig.run(item.id, JSON.stringify(item.configurations));

        statements.deleteFts.run(item.id);
        statements.insertFts.run(item.id, item.description, item.references.join(' '));

        // Alert Generation
        for (const wl of activeWatchlists) {
            if (matchesQuery(item, wl.query)) {
                const type = existing ? 'UPDATED_MATCH' : 'NEW_MATCH';
                statements.insertAlert.run(item.id, wl.id, wl.name, type, getTimestamp());
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
