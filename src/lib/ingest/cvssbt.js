/**
 * CVSS-BT Enrichment Ingestion
 * Downloads and parses the cvss-bt.csv from t0sche/cvss-bt repository
 * Enriches CVE data with EPSS scores, exploit maturity, and threat intelligence flags
 */

import getDb from '../db.js';
import { JobLogger, getTimestamp } from './nvd.js';
import https from 'https';
import { createInterface } from 'readline';

const CVSS_BT_URL = 'https://raw.githubusercontent.com/t0sche/cvss-bt/main/cvss-bt.csv';
const BATCH_SIZE = 5000;
const PROGRESS_UPDATE_INTERVAL = 10000;

// Extract exploit maturity from CVSS vector string (e.g., "E:POC" or "E:H")
function extractExploitMaturity(vector) {
    if (!vector) return 'U'; // Unproven if no vector
    const match = vector.match(/E:([A-Z]+)/i);
    if (!match) return 'U';

    // Map abbreviations to full values
    const maturityMap = {
        'A': 'A',      // Attacked
        'H': 'H',      // High
        'F': 'F',      // Functional
        'POC': 'POC',  // Proof-of-Concept
        'P': 'POC',    // Alternate for PoC
        'U': 'U',      // Unproven
        'X': 'U'       // Not Defined -> Unproven
    };

    return maturityMap[match[1].toUpperCase()] || 'U';
}

// Parse boolean string from CSV
function parseBool(val) {
    return val?.toLowerCase() === 'true' ? 1 : 0;
}

// Download and parse the CVSS-BT CSV
async function fetchCvssBtData(logger) {
    return new Promise((resolve, reject) => {
        logger.info('Downloading cvss-bt.csv...');

        https.get(CVSS_BT_URL, (response) => {
            if (response.statusCode === 302 || response.statusCode === 301) {
                // Handle redirect
                https.get(response.headers.location, handleResponse);
                return;
            }
            handleResponse(response);

            function handleResponse(res) {
                if (res.statusCode !== 200) {
                    reject(new Error(`Failed to download CVSS-BT CSV: HTTP ${res.statusCode}`));
                    return;
                }

                const records = [];
                let lineCount = 0;
                let isHeader = true;

                const rl = createInterface({
                    input: res,
                    crlfDelay: Infinity
                });

                rl.on('line', (line) => {
                    lineCount++;

                    // Skip header row
                    if (isHeader) {
                        isHeader = false;
                        return;
                    }

                    // Parse CSV line (simple split - no quotes in this data)
                    const cols = line.split(',');
                    if (cols.length < 17) return; // Skip malformed rows

                    const [
                        cve,
                        cvss_bt_score,
                        cvss_bt_severity,
                        cvss_bt_vector,
                        cvss_version,
                        base_score,
                        base_severity,
                        base_vector,
                        assigner,
                        published_date,
                        epss,
                        cisa_kev,
                        vulncheck_kev,
                        exploitdb,
                        metasploit,
                        nuclei,
                        poc_github
                    ] = cols;

                    records.push({
                        cve_id: cve,
                        epss: parseFloat(epss) || 0,
                        exploit_maturity: extractExploitMaturity(cvss_bt_vector),
                        cvss_bt_score: parseFloat(cvss_bt_score) || null,
                        cvss_bt_severity: cvss_bt_severity || null,
                        cisa_kev: parseBool(cisa_kev),
                        vulncheck_kev: parseBool(vulncheck_kev),
                        exploitdb: parseBool(exploitdb),
                        metasploit: parseBool(metasploit),
                        nuclei: parseBool(nuclei),
                        poc_github: parseBool(poc_github)
                    });

                    // Log progress every 50k records
                    if (lineCount % 50000 === 0) {
                        logger.info(`Parsed ${lineCount.toLocaleString()} rows...`);
                    }
                });

                rl.on('close', () => {
                    logger.info(`Parsed ${records.length.toLocaleString()} CVE records from CSV`);
                    resolve(records);
                });

                rl.on('error', reject);
            }
        }).on('error', reject);
    });
}

// Main ingestion function (internal, takes jobId)
async function runCvssBtIngest(jobId) {
    const db = getDb();
    const logger = new JobLogger(jobId, db);

    let processed = 0;
    let added = 0;
    let skipped = 0;
    let totalRecords = 0;
    let lastProgressUpdate = 0;

    // Update progress helper
    const updateProgress = async (phase) => {
        const now = Date.now();
        if (now - lastProgressUpdate > 1000 || processed % PROGRESS_UPDATE_INTERVAL === 0) {
            const percent = totalRecords > 0 ? Math.round((processed / totalRecords) * 100) : 0;
            await db.run(`
                UPDATE job_runs SET
                  progress_percent = ?, items_processed = ?, items_added = ?,
                  current_phase = ?, last_heartbeat = ?, total_files = ?
                WHERE id = ?
            `, percent, processed, added, phase, getTimestamp(), totalRecords, jobId);
            lastProgressUpdate = now;
        }
    };

    try {
        await logger.info('Starting CVSS-BT enrichment ingestion...');
        await updateProgress('DOWNLOADING');

        // Download and parse CSV
        const records = await fetchCvssBtData(logger);
        totalRecords = records.length;

        if (records.length === 0) {
            await logger.warn('No records to import');
            await db.run(
                'UPDATE job_runs SET end_time = ?, status = ?, items_processed = ?, error = ? WHERE id = ?',
                getTimestamp(), 'COMPLETED', 0, 'No records to import', jobId
            );
            return;
        }

        await updateProgress('LOADING_CVES');
        await logger.info('Loading existing CVE IDs from database...');

        // Check which CVEs exist in our database
        const existingCves = new Set();
        const rows = await db.all('SELECT id FROM cves');
        for (const row of rows) {
            existingCves.add(row.id);
        }
        await logger.info('Loaded CVE database', { cveCount: existingCves.size });

        await updateProgress('PROCESSING');

        // Process records in batches
        for (let i = 0; i < records.length; i += BATCH_SIZE) {
            const batch = records.slice(i, i + BATCH_SIZE);

            for (const record of batch) {
                processed++;

                // Only insert if CVE exists in our database
                if (!existingCves.has(record.cve_id)) {
                    skipped++;
                    continue;
                }

                // Upsert into cve_temporal table
                await db.run(`
                    INSERT INTO cve_temporal (
                        cve_id, epss, exploit_maturity, cvss_bt_score, cvss_bt_severity,
                        cisa_kev, vulncheck_kev, exploitdb, metasploit, nuclei, poc_github,
                        last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(cve_id) DO UPDATE SET
                        epss = excluded.epss,
                        exploit_maturity = excluded.exploit_maturity,
                        cvss_bt_score = excluded.cvss_bt_score,
                        cvss_bt_severity = excluded.cvss_bt_severity,
                        cisa_kev = excluded.cisa_kev,
                        vulncheck_kev = excluded.vulncheck_kev,
                        exploitdb = excluded.exploitdb,
                        metasploit = excluded.metasploit,
                        nuclei = excluded.nuclei,
                        poc_github = excluded.poc_github,
                        last_updated = datetime('now')
                `, record.cve_id, record.epss, record.exploit_maturity,
                   record.cvss_bt_score, record.cvss_bt_severity,
                   record.cisa_kev, record.vulncheck_kev, record.exploitdb,
                   record.metasploit, record.nuclei, record.poc_github);

                added++;
            }

            // Log batch progress
            if ((i + BATCH_SIZE) % 50000 === 0 || i + BATCH_SIZE >= records.length) {
                await logger.info('Batch processed', {
                    processed: Math.min(i + BATCH_SIZE, records.length),
                    total: records.length,
                    enriched: added,
                    skipped
                });
            }

            await updateProgress('PROCESSING');
        }

        await logger.info('CVSS-BT enrichment complete', {
            enriched: added,
            skipped
        });

        await db.run(
            'UPDATE job_runs SET end_time = ?, status = ?, items_processed = ?, items_added = ?, items_unchanged = ?, error = ? WHERE id = ?',
            getTimestamp(), 'COMPLETED', processed, added, skipped, '', jobId
        );

    } catch (err) {
        await logger.error('CVSS-BT ingestion failed', { error: err.message, stack: err.stack });
        await db.run(
            'UPDATE job_runs SET end_time = ?, status = ?, items_processed = ?, items_added = ?, error = ? WHERE id = ?',
            getTimestamp(), 'FAILED', processed, added, err.message, jobId
        );
    }
}

// Public run function - creates job and starts ingestion
export async function run() {
    const db = getDb();
    const timestamp = getTimestamp();
    const result = await db.run(
        "INSERT INTO job_runs (start_time, status, items_processed, last_heartbeat, current_phase) VALUES (?, 'RUNNING', 0, ?, 'CVSSBT_SYNC')",
        timestamp, timestamp
    );
    const jobId = result.lastID;

    // Run in background (don't await)
    runCvssBtIngest(jobId).catch(err => console.error('CVSS-BT ingest error:', err));

    return jobId;
}

// Legacy function for backwards compatibility (deprecated)
export async function ingestCvssBt(logger = console) {
    console.warn('[CVSS-BT] ingestCvssBt() is deprecated, use run() instead');
    const db = getDb();

    // Create a temporary job for this run
    const timestamp = getTimestamp();
    const result = await db.run(
        "INSERT INTO job_runs (start_time, status, items_processed, last_heartbeat, current_phase) VALUES (?, 'RUNNING', 0, ?, 'CVSSBT_SYNC')",
        timestamp, timestamp
    );
    const jobId = result.lastID;

    await runCvssBtIngest(jobId);

    // Return stats for backwards compatibility
    const job = await db.get('SELECT * FROM job_runs WHERE id = ?', jobId);
    return {
        added: job?.items_added || 0,
        updated: 0,
        skipped: job?.items_unchanged || 0
    };
}

// Export for testing
export { fetchCvssBtData };

export default { run, ingestCvssBt, fetchCvssBtData };
