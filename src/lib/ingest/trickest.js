/**
 * Trickest CVE PoC Ingestion
 * Clones/pulls the trickest/cve repository and extracts exploit links
 * Source: https://github.com/trickest/cve
 */

import getDb from '../db.js';
import { JobLogger, getTimestamp } from './nvd.js';
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const TRICKEST_REPO = 'https://github.com/trickest/cve.git';
const TRICKEST_DIR = path.resolve(process.cwd(), 'data', 'trickest-cve');
const BATCH_SIZE = 500;
const PROGRESS_UPDATE_INTERVAL = 1000;

// Categorize URL by source
function categorizeUrl(url) {
    if (url.includes('github.com')) return 'github';
    if (url.includes('exploit-db.com')) return 'exploitdb';
    if (url.includes('packetstormsecurity.com')) return 'packetstorm';
    if (url.includes('rapid7.com') || url.includes('metasploit')) return 'metasploit';
    if (url.includes('nuclei-templates')) return 'nuclei';
    if (url.includes('cisa.gov')) return 'cisa';
    if (url.includes('hackerone.com')) return 'hackerone';
    return 'reference';
}

// Parse a Trickest markdown file to extract exploit links
function parseMarkdownFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    // Extract CVE ID from filename
    const filename = path.basename(filePath, '.md');
    const cveMatch = filename.match(/^(CVE-\d{4}-\d+)/i);
    if (!cveMatch) return null;

    const cveId = cveMatch[1].toUpperCase();
    const exploits = [];

    let inPocSection = false;
    let currentSection = null;

    for (const line of lines) {
        // Detect POC section
        if (line.trim() === '### POC') {
            inPocSection = true;
            continue;
        }

        // Detect subsections within POC
        if (line.startsWith('#### Reference')) {
            currentSection = 'reference';
            continue;
        }
        if (line.startsWith('#### Github')) {
            currentSection = 'github';
            continue;
        }

        // End of POC section (next major heading)
        if (inPocSection && line.startsWith('### ') && !line.includes('POC')) {
            break;
        }

        // Extract URLs from list items
        if (inPocSection && line.trim().startsWith('- http')) {
            const url = line.trim().substring(2).trim();
            if (url.startsWith('http')) {
                const source = currentSection === 'github' ? 'github' : categorizeUrl(url);
                exploits.push({
                    cve_id: cveId,
                    source,
                    url,
                    description: null
                });
            }
        }
    }

    return { cveId, exploits };
}

// Clone or pull the Trickest repository
async function syncRepository(logger) {
    const dataDir = path.dirname(TRICKEST_DIR);

    // Ensure data directory exists
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
    }

    if (fs.existsSync(TRICKEST_DIR)) {
        // Pull updates
        await logger.info('Pulling latest changes from Trickest repository...');
        const result = spawnSync('git', ['pull', '--ff-only'], {
            cwd: TRICKEST_DIR,
            timeout: 300000, // 5 minutes
            stdio: ['pipe', 'pipe', 'pipe']
        });

        if (result.status !== 0) {
            const stderr = result.stderr?.toString() || '';
            throw new Error(`Git pull failed: ${stderr}`);
        }

        await logger.info('Trickest repository updated');
    } else {
        // Clone repository (shallow for speed)
        await logger.info('Cloning Trickest repository (this may take a few minutes)...');
        const result = spawnSync('git', ['clone', '--depth', '1', TRICKEST_REPO, TRICKEST_DIR], {
            timeout: 600000, // 10 minutes
            stdio: ['pipe', 'pipe', 'pipe']
        });

        if (result.status !== 0) {
            const stderr = result.stderr?.toString() || '';
            throw new Error(`Git clone failed: ${stderr}`);
        }

        await logger.info('Trickest repository cloned');
    }
}

// Walk directory and find all CVE markdown files
function* walkCveFiles(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
            // Recurse into year directories (2020, 2021, etc.)
            if (/^\d{4}$/.test(entry.name)) {
                yield* walkCveFiles(fullPath);
            }
        } else if (entry.isFile() && entry.name.endsWith('.md')) {
            // Only process CVE files
            if (entry.name.startsWith('CVE-')) {
                yield fullPath;
            }
        }
    }
}

// Count total files for progress tracking
function countFiles(dir) {
    let count = 0;
    for (const _ of walkCveFiles(dir)) {
        count++;
    }
    return count;
}

// Main ingestion function (internal, takes jobId)
async function runTrickestIngest(jobId) {
    const db = getDb();
    const logger = new JobLogger(jobId, db);

    let filesProcessed = 0;
    let exploitsAdded = 0;
    let cvesWithExploits = 0;
    let skipped = 0;
    let totalFiles = 0;
    let lastProgressUpdate = 0;

    // Update progress helper
    const updateProgress = async (phase) => {
        const now = Date.now();
        if (now - lastProgressUpdate > 1000 || filesProcessed % PROGRESS_UPDATE_INTERVAL === 0) {
            const percent = totalFiles > 0 ? Math.round((filesProcessed / totalFiles) * 100) : 0;
            await db.run(`
                UPDATE job_runs SET
                  progress_percent = ?, items_processed = ?, items_added = ?,
                  current_phase = ?, last_heartbeat = ?, total_files = ?
                WHERE id = ?
            `, percent, filesProcessed, exploitsAdded, phase, getTimestamp(), totalFiles, jobId);
            lastProgressUpdate = now;
        }
    };

    try {
        await logger.info('Starting Trickest CVE exploit ingestion...');
        await updateProgress('PREPARING_REPO');

        // Sync repository
        await syncRepository(logger);

        // Check if repository exists
        if (!fs.existsSync(TRICKEST_DIR)) {
            throw new Error('Trickest repository not found after sync');
        }

        await updateProgress('SCANNING_FILES');
        await logger.info('Counting files in Trickest repository...');
        totalFiles = countFiles(TRICKEST_DIR);
        await logger.info('File count complete', { totalFiles });

        // Check which CVEs exist in our database
        const existingCves = new Set();
        const rows = await db.all('SELECT id FROM cves');
        for (const row of rows) {
            existingCves.add(row.id);
        }
        await logger.info('Loaded CVE database', { cveCount: existingCves.size });

        await updateProgress('PROCESSING');

        // Process files
        let batch = [];

        for (const filePath of walkCveFiles(TRICKEST_DIR)) {
            filesProcessed++;

            try {
                const result = parseMarkdownFile(filePath);
                if (!result) continue;

                const { cveId, exploits } = result;

                // Skip if CVE not in our database
                if (!existingCves.has(cveId)) {
                    skipped++;
                    continue;
                }

                if (exploits.length > 0) {
                    batch.push({ cveId, exploits });
                }

                // Process batch
                if (batch.length >= BATCH_SIZE) {
                    // Delete old exploits and insert new ones
                    for (const { cveId, exploits } of batch) {
                        await db.run('DELETE FROM cve_exploits WHERE cve_id = ?', cveId);
                        for (const exploit of exploits) {
                            await db.run(
                                'INSERT OR IGNORE INTO cve_exploits (cve_id, source, url, description) VALUES (?, ?, ?, ?)',
                                exploit.cve_id, exploit.source, exploit.url, exploit.description
                            );
                            exploitsAdded++;
                        }
                        cvesWithExploits++;
                    }

                    await logger.info('Batch processed', {
                        filesProcessed,
                        exploitsAdded,
                        cvesWithExploits
                    });
                    batch = [];
                    await updateProgress('PROCESSING');
                }
            } catch (err) {
                // Skip individual file errors
                await logger.warn(`Error parsing file: ${err.message}`, { filePath });
            }
        }

        // Process remaining batch
        if (batch.length > 0) {
            for (const { cveId, exploits } of batch) {
                await db.run('DELETE FROM cve_exploits WHERE cve_id = ?', cveId);
                for (const exploit of exploits) {
                    await db.run(
                        'INSERT OR IGNORE INTO cve_exploits (cve_id, source, url, description) VALUES (?, ?, ?, ?)',
                        exploit.cve_id, exploit.source, exploit.url, exploit.description
                    );
                    exploitsAdded++;
                }
                cvesWithExploits++;
            }
        }

        await logger.info('Trickest ingestion complete', {
            filesProcessed,
            cvesWithExploits,
            exploitsAdded,
            skipped
        });

        await db.run(
            'UPDATE job_runs SET end_time = ?, status = ?, items_processed = ?, items_added = ?, error = ? WHERE id = ?',
            getTimestamp(), 'COMPLETED', filesProcessed, exploitsAdded, '', jobId
        );

    } catch (err) {
        await logger.error('Trickest ingestion failed', { error: err.message, stack: err.stack });
        await db.run(
            'UPDATE job_runs SET end_time = ?, status = ?, items_processed = ?, items_added = ?, error = ? WHERE id = ?',
            getTimestamp(), 'FAILED', filesProcessed, exploitsAdded, err.message, jobId
        );
    }
}

// Public run function - creates job and starts ingestion
export async function run() {
    const db = getDb();
    const timestamp = getTimestamp();
    const result = await db.run(
        "INSERT INTO job_runs (start_time, status, items_processed, last_heartbeat, current_phase) VALUES (?, 'RUNNING', 0, ?, 'TRICKEST_SYNC')",
        timestamp, timestamp
    );
    const jobId = result.lastID;

    // Run in background (don't await)
    runTrickestIngest(jobId).catch(err => console.error('Trickest ingest error:', err));

    return jobId;
}

// Legacy function for backwards compatibility (deprecated)
export async function ingestTrickest(logger = console) {
    // For backwards compatibility, run synchronously without job tracking
    console.warn('[Trickest] ingestTrickest() is deprecated, use run() instead');
    const db = getDb();

    // Create a temporary job for this run
    const timestamp = getTimestamp();
    const result = await db.run(
        "INSERT INTO job_runs (start_time, status, items_processed, last_heartbeat, current_phase) VALUES (?, 'RUNNING', 0, ?, 'TRICKEST_SYNC')",
        timestamp, timestamp
    );
    const jobId = result.lastID;

    await runTrickestIngest(jobId);

    // Return stats for backwards compatibility
    const job = await db.get('SELECT * FROM job_runs WHERE id = ?', jobId);
    return {
        filesProcessed: job?.items_processed || 0,
        cvesWithExploits: 0,
        exploitsAdded: job?.items_added || 0,
        skipped: 0
    };
}

export default { run, ingestTrickest };
