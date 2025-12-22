const fs = require('node:fs');
const path = require('node:path');
const { execSync, spawn } = require('node:child_process');
const crypto = require('node:crypto');
const db = require('../db');

// --- Configuration ---
const DATA_DIR = path.resolve(process.cwd(), 'data');
const REPO_DIR = path.join(DATA_DIR, 'cvelistV5');
const REPO_URL = 'https://github.com/CVEProject/cvelistV5';
const BATCH_SIZE = 100; // Database transaction batch size

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

// Recursively find all JSON files in a directory
function getAllFiles(dir, fileList = []) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const filePath = path.join(dir, file);
        if (fs.statSync(filePath).isDirectory()) {
            getAllFiles(filePath, fileList);
        } else if (file.endsWith('.json') && !file.endsWith('delta.json') && !file.endsWith('deltaLog.json')) {
            fileList.push(filePath);
        }
    }
    return fileList;
}

// --- Git Operations ---
function gitExec(args, cwd = REPO_DIR) {
    try {
        return execSync(`git ${args}`, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch (e) {
        // Simple error handling for git commands
        throw new Error(`Git command failed: git ${args}`);
    }
}

async function prepareRepo() {
    ensureDir(DATA_DIR);
    
    if (!fs.existsSync(path.join(REPO_DIR, '.git'))) {
        console.log('[Ingest] Cloning cvelistV5 (this may take a few minutes)...');
        // Use depth 1 for speed, but note: shallow clones limit history for diffs if we skip updates too long.
        // However, for a simple "last run" diff, we might need more depth if we miss commits.
        // To be safe for incremental updates, we clone fully or fetch appropriately. 
        // For V1, let's do depth 1 and rely on 'git pull' fetching what's needed.
        execSync(`git clone --depth 1 ${REPO_URL} ${REPO_DIR}`, { stdio: 'inherit' });
        return { mode: 'full', oldHash: null, newHash: gitExec('rev-parse HEAD') };
    } else {
        console.log('[Ingest] Pulling updates...');
        const oldHash = gitExec('rev-parse HEAD');
        try {
            execSync('git pull', { cwd: REPO_DIR, stdio: 'inherit' });
        } catch (e) {
            console.warn('[Ingest] Git pull failed (might be network), trying to proceed with local data.');
        }
        const newHash = gitExec('rev-parse HEAD');
        
        if (oldHash === newHash) {
            // Check if we actually have data in DB. If empty DB, force full scan.
            const count = db.prepare('SELECT count(*) as c FROM cves').get().c;
            if (count === 0) return { mode: 'full', oldHash, newHash };
            return { mode: 'incremental', oldHash, newHash, noChanges: true };
        }
        
        return { mode: 'incremental', oldHash, newHash };
    }
}

function getChangedFiles(oldHash, newHash) {
    try {
        // Get list of changed files between commits
        const diffOutput = gitExec(`diff --name-only ${oldHash} ${newHash}`);
        return diffOutput.split('\n')
            .filter(line => line.startsWith('cves/') && line.endsWith('.json'))
            .map(line => path.join(REPO_DIR, line));
    } catch (e) {
        console.warn('[Ingest] Failed to calc diff, falling back to full scan.', e.message);
        return getAllFiles(path.join(REPO_DIR, 'cves'));
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
    
    // Description
    const descObj = cna.descriptions?.find(d => d.lang === 'en') || cna.descriptions?.[0];
    const description = descObj ? descObj.value : 'No description available';

    // Metrics
    let score = null;
    let severity = null;
    let vector = null;
    let cvssVersion = null;

    // Search for CVSS v3.1, then v3.0, then v2.0
    const metrics = cna.metrics || [];
    for (const m of metrics) {
        if (m.cvssV3_1) {
            score = m.cvssV3_1.baseScore;
            severity = m.cvssV3_1.baseSeverity;
            vector = m.cvssV3_1.vectorString;
            cvssVersion = '3.1';
            break;
        }
        if (m.cvssV3_0) {
            score = m.cvssV3_0.baseScore;
            severity = m.cvssV3_0.baseSeverity;
            vector = m.cvssV3_0.vectorString;
            cvssVersion = '3.0';
            break;
        }
    }
    // Fallback to V2 if no V3 found
    if (!cvssVersion) {
        for (const m of metrics) {
             if (m.cvssV2_0) {
                score = m.cvssV2_0.baseScore;
                severity = m.cvssV2_0.baseSeverity || 'UNKNOWN'; // V2 often lacks explicit severity text in JSON
                vector = m.cvssV2_0.vectorString;
                cvssVersion = '2.0';
                break;
            }
        }
    }

    // References
    const refs = (cna.references || []).map(r => r.url).sort();
    
    // KEV (Not explicitly in V5 JSON usually, requires enrichment or checking tags. 
    // For now false unless we overlay KEV list separately, or check tags)
    const kev = (cna.tags || []).includes('exclusively-hosted-service'); // Example tag, unlikely to match KEV. 
    // We will default KEV to false here as V5 doesn't strictly carry it like NVD API does.

    // Configurations (Simplistic extraction of product names)
    const configurations = [];
    if (cna.affected) {
        for (const aff of cna.affected) {
            if (aff.product) configurations.push({ product: aff.product, vendor: aff.vendor });
        }
    }

    return {
        id,
        description,
        published,
        lastModified,
        vulnStatus,
        cvssVersion,
        score,
        severity,
        vector,
        kev: false, // cvelistV5 doesn't have CISA KEV flag by default
        references: refs,
        configurations
    };
}

// --- Database Statements ---
const getCveHash = db.prepare('SELECT normalized_hash, json FROM cves WHERE id = ?');
const upsertCve = db.prepare(`
  INSERT INTO cves (id, description, published, last_modified, vuln_status, normalized_hash, json)
  VALUES (@id, @description, @published, @lastModified, @vulnStatus, @hash, @json)
  ON CONFLICT(id) DO UPDATE SET
    description = excluded.description,
    published = excluded.published,
    last_modified = excluded.last_modified,
    vuln_status = excluded.vuln_status,
    normalized_hash = excluded.normalized_hash,
    json = excluded.json
`);
const deleteMetrics = db.prepare('DELETE FROM metrics WHERE cve_id = ?');
const insertMetric = db.prepare('INSERT INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES (?, ?, ?, ?, ?)');
const deleteRefs = db.prepare('DELETE FROM references WHERE cve_id = ?');
const insertRef = db.prepare('INSERT INTO references (cve_id, url) VALUES (?, ?)');
const deleteConfigs = db.prepare('DELETE FROM configs WHERE cve_id = ?');
const insertConfig = db.prepare('INSERT INTO configs (cve_id, nodes) VALUES (?, ?)');
const deleteFts = db.prepare('DELETE FROM cves_fts WHERE id = ?');
const insertFts = db.prepare('INSERT INTO cves_fts (id, description, refs) VALUES (?, ?, ?)');
const insertChange = db.prepare('INSERT INTO cve_changes (cve_id, change_date, diff_json) VALUES (?, ?, ?)');
const insertJob = db.prepare("INSERT INTO job_runs (start_time, status, items_processed) VALUES (?, 'RUNNING', 0) RETURNING id");
const updateJob = db.prepare("UPDATE job_runs SET end_time = ?, status = ?, items_processed = ?, error = ? WHERE id = ?");
const setMeta = db.prepare("INSERT INTO system_metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");

const processBatch = db.transaction((batch) => {
    let changed = 0;
    for (const item of batch) {
        const hash = computeHash(item);
        const existing = getCveHash.get(item.id);
        
        if (existing && existing.normalized_hash === hash) continue;

        const row = {
            id: item.id,
            description: item.description,
            published: item.published,
            lastModified: item.lastModified,
            vulnStatus: item.vulnStatus,
            hash,
            json: JSON.stringify(item)
        };

        if (existing) {
            const oldJson = JSON.parse(existing.json);
            const diff = getDiff(oldJson, item);
            if (Object.keys(diff).length > 0) {
                insertChange.run(item.id, getTimestamp(), JSON.stringify(diff));
            }
        }

        upsertCve.run(row);
        
        deleteMetrics.run(item.id);
        if (item.score !== null) insertMetric.run(item.id, item.cvssVersion, item.score, item.severity, item.vector);

        deleteRefs.run(item.id);
        for (const url of item.references) insertRef.run(item.id, url);

        deleteConfigs.run(item.id);
        if (item.configurations.length > 0) insertConfig.run(item.id, JSON.stringify(item.configurations));

        deleteFts.run(item.id);
        insertFts.run(item.id, item.description, item.references.join(' '));
        
        changed++;
    }
    return changed;
});

// --- Main Ingest Logic ---

async function runIngest(jobId) {
    let totalProcessed = 0;
    try {
        const { mode, oldHash, newHash, noChanges } = await prepareRepo();
        
        if (noChanges) {
            console.log('[Ingest] No changes detected in repo.');
            updateJob.run(getTimestamp(), 'COMPLETED', 0, 'No updates found', jobId);
            return;
        }

        let files = [];
        if (mode === 'full') {
            console.log('[Ingest] Full scan required. Listing all files...');
            files = getAllFiles(path.join(REPO_DIR, 'cves'));
        } else {
            console.log(`[Ingest] Incremental scan (${oldHash.substring(0,7)}...${newHash.substring(0,7)})`);
            files = getChangedFiles(oldHash, newHash);
        }

        console.log(`[Ingest] Found ${files.length} files to process.`);
        
        let batch = [];
        for (let i = 0; i < files.length; i++) {
            const filePath = files[i];
            if (!fs.existsSync(filePath)) continue; // File might be deleted in a commit
            
            try {
                const content = fs.readFileSync(filePath, 'utf8');
                const raw = JSON.parse(content);
                const normalized = normalizeCve5(raw);
                batch.push(normalized);
            } catch (err) {
                console.warn(`[Ingest] Failed to parse ${filePath}:`, err.message);
            }

            if (batch.length >= BATCH_SIZE) {
                processBatch(batch);
                totalProcessed += batch.length;
                batch = [];
                // Periodic update
                updateJob.run(null, 'RUNNING', totalProcessed, null, jobId);
                // Allow event loop to tick
                await sleep(5);
            }
        }

        if (batch.length > 0) {
            processBatch(batch);
            totalProcessed += batch.length;
        }

        // Save state
        setMeta.run('cvelist_commit', newHash);
        updateJob.run(getTimestamp(), 'COMPLETED', totalProcessed, null, jobId);
        console.log(`[Ingest] Job ${jobId} completed. ${totalProcessed} items processed.`);

    } catch (err) {
        console.error('[Ingest] Critical Failure:', err);
        updateJob.run(getTimestamp(), 'FAILED', totalProcessed, err.message, jobId);
    }
}

function run() {
    const jobId = insertJob.get(getTimestamp()).id;
    // Run async
    runIngest(jobId).catch(err => console.error('Unhandled ingest error:', err));
    return jobId;
}

module.exports = { run };
