import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';
import getDb, { initPromise } from './lib/db.js';
import * as nvd from './lib/ingest/nvd.js';

// Wait for database to be ready
let db;
async function ensureDbReady() {
  if (!db) {
    await initPromise;
    db = getDb();
  }
  return db;
}

const PORT = process.env.PORT || 17920;

// BigInt replacer for JSON.stringify (DuckDB returns BigInt for counts)
const bigIntReplacer = (key, value) =>
  typeof value === 'bigint' ? Number(value) : value;

const sendJson = (res, data, status = 200) => {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });
  res.end(JSON.stringify(data, bigIntReplacer));
};

const sendError = (res, message, status = 500) => {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify({ error: message }));
};

// Validation constants
const MAX_BODY_SIZE = 1024 * 1024; // 1MB limit
const MAX_SEARCH_LENGTH = 500;
const MAX_LIMIT = 1000;
const MIN_LIMIT = 1;
const DEFAULT_LIMIT = 100;
const VALID_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const MAX_WATCHLIST_NAME_LENGTH = 255;

// Validation helper for watchlist body
const validateWatchlistBody = (body) => {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { error: 'Request body must be a JSON object' };
  }
  if (!body.name || typeof body.name !== 'string') {
    return { error: 'name is required and must be a string' };
  }
  if (body.name.trim().length === 0) {
    return { error: 'name cannot be empty' };
  }
  if (body.name.length > MAX_WATCHLIST_NAME_LENGTH) {
    return { error: `name must be ${MAX_WATCHLIST_NAME_LENGTH} characters or less` };
  }
  if (!body.query || typeof body.query !== 'object' || Array.isArray(body.query)) {
    return { error: 'query is required and must be an object' };
  }
  return null; // Valid
};

const readBody = (req) => new Promise((resolve, reject) => {
  let body = '';
  let size = 0;
  req.on('data', chunk => {
    size += chunk.length;
    if (size > MAX_BODY_SIZE) {
      req.destroy();
      reject(new Error('Request body too large'));
      return;
    }
    body += chunk;
  });
  req.on('end', () => {
    try {
      resolve(body ? JSON.parse(body) : {});
    } catch (e) {
      reject(e);
    }
  });
  req.on('error', reject);
});

async function handleRequest(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  console.log(`${req.method} ${pathname}`);

  // Ensure database is ready for all API requests
  await ensureDbReady();

  try {
    // --- Ingestion ---
    if (req.method === 'POST' && pathname === '/api/ingest') {
      console.log('[API] Triggering ingestion job...');
      try {
        const jobId = await nvd.run();
        return sendJson(res, { status: 'Ingestion started', jobId }, 202);
      } catch (e) {
        console.error("Failed to start ingestion job:", e);
        return sendError(res, 'Failed to start ingestion job: ' + e.message, 500);
      }
    }

    // Bulk ingestion (faster, skips per-row FTS/alerts, rebuilds at end)
    if (req.method === 'POST' && pathname === '/api/ingest/bulk') {
      console.log('[API] Triggering BULK ingestion job (fast mode)...');
      try {
        const jobId = await nvd.runBulk();
        return sendJson(res, { status: 'Bulk ingestion started (fast mode)', jobId }, 202);
      } catch (e) {
        console.error("Failed to start bulk ingestion job:", e);
        return sendError(res, 'Failed to start bulk ingestion job: ' + e.message, 500);
      }
    }

    // --- CVEs ---
    if (req.method === 'GET' && pathname === '/api/cves') {
      // Validate search parameter
      const search = url.searchParams.get('search') || '';
      if (search.length > MAX_SEARCH_LENGTH) {
        return sendError(res, `Search query too long (max ${MAX_SEARCH_LENGTH} characters)`, 400);
      }

      // Validate and bound limit parameter
      const rawLimit = parseInt(url.searchParams.get('limit'));
      const limit = isNaN(rawLimit) ? DEFAULT_LIMIT : Math.min(Math.max(rawLimit, MIN_LIMIT), MAX_LIMIT);

      // Validate offset is non-negative
      const rawOffset = parseInt(url.searchParams.get('offset'));
      const offset = isNaN(rawOffset) || rawOffset < 0 ? 0 : rawOffset;

      // Validate severity against enum
      const rawSeverity = url.searchParams.get('severity');
      const severity = rawSeverity ? rawSeverity.toUpperCase() : null;
      if (severity && !VALID_SEVERITIES.includes(severity)) {
        return sendError(res, `Invalid severity. Must be one of: ${VALID_SEVERITIES.join(', ')}`, 400);
      }

      // Validate CVSS scores are in valid range (0-10)
      const validateCvss = (val, name) => {
        if (val === null || isNaN(val)) return null;
        if (val < 0 || val > 10) {
          return { error: `${name} must be between 0 and 10` };
        }
        return val;
      };

      const cvssMinRaw = parseFloat(url.searchParams.get('cvss_min'));
      const cvss2MinRaw = parseFloat(url.searchParams.get('cvss2_min'));
      const cvss30MinRaw = parseFloat(url.searchParams.get('cvss30_min'));
      const cvss31MinRaw = parseFloat(url.searchParams.get('cvss31_min'));

      const cvssMin = validateCvss(cvssMinRaw, 'cvss_min');
      const cvss2Min = validateCvss(cvss2MinRaw, 'cvss2_min');
      const cvss30Min = validateCvss(cvss30MinRaw, 'cvss30_min');
      const cvss31Min = validateCvss(cvss31MinRaw, 'cvss31_min');

      // Check for validation errors
      for (const val of [cvssMin, cvss2Min, cvss30Min, cvss31Min]) {
        if (val && val.error) {
          return sendError(res, val.error, 400);
        }
      }

      const kev = url.searchParams.get('kev');

      // Date range filtering
      const publishedFrom = url.searchParams.get('published_from');
      const publishedTo = url.searchParams.get('published_to');

      // Vendor/product filtering
      const vendorsParam = url.searchParams.get('vendors');
      const productsParam = url.searchParams.get('products');

      // Parse comma-separated vendors/products
      const vendors = vendorsParam ? vendorsParam.split(',').map(v => v.trim()).filter(v => v) : [];
      const products = productsParam ? productsParam.split(',').map(p => p.trim()).filter(p => p) : [];

      // Validate vendor/product array lengths
      if (vendors.length > 50) {
        return sendError(res, 'Too many vendors (max 50)', 400);
      }
      if (products.length > 50) {
        return sendError(res, 'Too many products (max 50)', 400);
      }

      // Validate date format (ISO date string YYYY-MM-DD)
      const isValidDate = (dateStr) => {
        if (!dateStr) return false;
        const date = new Date(dateStr);
        return !isNaN(date.getTime()) && /^\d{4}-\d{2}-\d{2}/.test(dateStr);
      };

      // Build base query to get CVEs with their JSON data
      // If filtering by vendor/product, use the denormalized cve_products table
      const needsProductsJoin = vendors.length > 0 || products.length > 0;
      let query = `
        SELECT ${needsProductsJoin ? 'DISTINCT' : ''} c.json, count(*) OVER() as total_count
        FROM cves c
        ${needsProductsJoin ? `JOIN cve_products cp ON cp.cve_id = c.id` : ''}
      `;
      const params = [];
      const where = [];
      let paramIndex = 1;

      if (search) {
        // Search using ILIKE on CVE ID and description
        where.push(`(c.id ILIKE $${paramIndex} OR c.description ILIKE $${paramIndex})`);
        const searchTerm = '%' + search.trim() + '%';
        params.push(searchTerm);
        paramIndex++;
      }

      // Handle filtering by severity
      if (severity) {
        where.push(`c.id IN (SELECT cve_id FROM metrics WHERE severity = $${paramIndex})`);
        params.push(severity); // Already uppercased during validation
        paramIndex++;
      }

      // General CVSS min filter: use MAX score to match UI display behavior
      // UI shows highest score across versions, so filter should match on highest
      if (cvssMin) {
        where.push(`c.id IN (SELECT cve_id FROM metrics GROUP BY cve_id HAVING MAX(score) >= $${paramIndex})`);
        params.push(cvssMin);
        paramIndex++;
      }

      // Version-specific CVSS filtering (filters on specific version's score)
      const versionConditions = [];
      if (cvss2Min) {
        versionConditions.push(`(cvss_version = $${paramIndex} AND score >= $${paramIndex + 1})`);
        params.push('2.0', cvss2Min);
        paramIndex += 2;
      }
      if (cvss30Min) {
        versionConditions.push(`(cvss_version = $${paramIndex} AND score >= $${paramIndex + 1})`);
        params.push('3.0', cvss30Min);
        paramIndex += 2;
      }
      if (cvss31Min) {
        versionConditions.push(`(cvss_version = $${paramIndex} AND score >= $${paramIndex + 1})`);
        params.push('3.1', cvss31Min);
        paramIndex += 2;
      }

      if (versionConditions.length > 0) {
        where.push(`c.id IN (SELECT cve_id FROM metrics WHERE ${versionConditions.join(' OR ')})`);
      }

      // KEV filtering - check for 'true', '1', or 1 (JSON values can vary)
      if (kev === 'true') {
        where.push("(json_extract_string(c.json, '$.kev') = 'true' OR json_extract_string(c.json, '$.kev') = '1')");
      }

      // Date range filtering
      if (publishedFrom && isValidDate(publishedFrom)) {
        where.push(`c.published >= $${paramIndex}`);
        params.push(publishedFrom + 'T00:00:00.000Z');
        paramIndex++;
      }
      if (publishedTo && isValidDate(publishedTo)) {
        where.push(`c.published <= $${paramIndex}`);
        params.push(publishedTo + 'T23:59:59.999Z');
        paramIndex++;
      }

      // Vendor filtering (OR logic within vendors) - uses denormalized cve_products table
      if (vendors.length > 0) {
        const vendorPlaceholders = vendors.map(() => {
          const placeholder = `cp.vendor = $${paramIndex}`;
          paramIndex++;
          return placeholder;
        }).join(' OR ');
        where.push(`(${vendorPlaceholders})`);
        params.push(...vendors);
      }

      // Product filtering (OR logic within products) - uses denormalized cve_products table
      if (products.length > 0) {
        const productPlaceholders = products.map(() => {
          const placeholder = `cp.product = $${paramIndex}`;
          paramIndex++;
          return placeholder;
        }).join(' OR ');
        where.push(`(${productPlaceholders})`);
        params.push(...products);
      }

      if (where.length > 0) {
        query += ` WHERE ` + where.join(' AND ');
      }

      query += ` ORDER BY c.published DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1} `;
      params.push(limit, offset);

      const rows = await db.all(query, ...params);
      const totalCount = rows.length > 0 ? rows[0].total_count : 0;

      // Get all metrics for the CVEs in this result set
      const cveIds = rows.map(r => {
        const data = JSON.parse(r.json);
        return data.id;
      });

      const metricsMap = new Map();
      if (cveIds.length > 0) {
        // Create placeholders for the IN clause (DuckDB uses $N)
        const placeholders = cveIds.map((_, i) => `$${i + 1}`).join(',');
        const metricsQuery = `SELECT cve_id, cvss_version, score, severity, vector_string FROM metrics WHERE cve_id IN (${placeholders})`;
        const metricsRows = await db.all(metricsQuery, ...cveIds);

        // Group metrics by CVE ID
        for (const metric of metricsRows) {
          if (!metricsMap.has(metric.cve_id)) {
            metricsMap.set(metric.cve_id, []);
          }
          metricsMap.get(metric.cve_id).push(metric);
        }
      }

      const cves = rows.map(r => {
        const data = JSON.parse(r.json);
        const cveMetrics = metricsMap.get(data.id) || [];

        // Extract version-specific metrics
        let cvss2Score = null, cvss2Severity = null;
        let cvss30Score = null, cvss30Severity = null;
        let cvss31Score = null, cvss31Severity = null;

        for (const metric of cveMetrics) {
          switch (metric.cvss_version) {
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
          id: data.id,
          description: data.description,
          // Primary score for backward compatibility
          cvssScore: data.score,
          cvssSeverity: data.severity,
          cvssVersion: data.cvssVersion,
          // Version-specific scores
          cvss2Score,
          cvss2Severity,
          cvss30Score,
          cvss30Severity,
          cvss31Score,
          cvss31Severity,
          published: data.published,
          lastModified: data.lastModified,
          epssScore: null,
          kev: data.kev,
          references: data.references
        };
      });

      res.setHeader('X-Total-Count', totalCount.toString());
      return sendJson(res, { cves, totalCount });
    }

    const cveMatch = pathname.match(/^\/api\/cves\/(CVE-\d+-\d+)$/);
    if (req.method === 'GET' && cveMatch) {
      const id = cveMatch[1];
      const row = await db.get('SELECT json, title, source_advisory FROM cves WHERE id = $1', id);
      if (!row) return sendJson(res, { error: 'Not found' }, 404);

      // Get all metrics for this CVE (single source of truth for CVSS data)
      const metricsRows = await db.all('SELECT cvss_version, score, severity, vector_string FROM metrics WHERE cve_id = $1', id);

      // Parse the base CVE data
      const cveData = JSON.parse(row.json);

      // Get affected products from configs table (includes version details)
      const configsRow = await db.get('SELECT nodes FROM configs WHERE cve_id = $1', id);
      let affectedProducts = [];
      if (configsRow && configsRow.nodes) {
        try {
          const nodes = JSON.parse(configsRow.nodes);
          // Keep all entries with their version info (no deduplication to preserve version data)
          for (const node of nodes) {
            if (node.vendor && node.product) {
              affectedProducts.push({
                vendor: node.vendor,
                product: node.product,
                defaultStatus: node.defaultStatus || null,
                modules: node.modules || [],
                versions: node.versions || []
              });
            }
          }
        } catch (e) {
          // Ignore JSON parse errors
        }
      }

      // Get CWE classifications
      const cwes = await db.all('SELECT cwe_id, description FROM cve_cwes WHERE cve_id = $1', id);

      // Get CAPEC attack patterns
      const capecs = await db.all('SELECT capec_id, description FROM cve_capec WHERE cve_id = $1', id);

      // Get SSVC scores (CISA prioritization)
      const ssvc = await db.all('SELECT exploitation, automatable, technical_impact, provider FROM cve_ssvc WHERE cve_id = $1', id);

      // Get references with tags
      const referencesRaw = await db.all('SELECT url, tags FROM cve_references WHERE cve_id = $1', id);
      const references = referencesRaw.map(r => ({
        url: r.url,
        tags: r.tags ? JSON.parse(r.tags) : []
      }));

      // Get change history
      const changeHistoryRaw = await db.all('SELECT change_date, diff_json FROM cve_changes WHERE cve_id = $1 ORDER BY change_date DESC LIMIT 50', id);
      const changeHistory = changeHistoryRaw.map(c => ({
        date: c.change_date,
        changes: JSON.parse(c.diff_json)
      }));

      // Get workarounds
      const workarounds = await db.all('SELECT workaround_text, language FROM cve_workarounds WHERE cve_id = $1', id);

      // Get solutions
      const solutions = await db.all('SELECT solution_text, language FROM cve_solutions WHERE cve_id = $1', id);

      // Build enhanced response (metrics array is single source of truth for CVSS)
      const enhancedCveData = {
        ...cveData,
        title: row.title || cveData.title || null,
        sourceAdvisory: row.source_advisory || cveData.sourceAdvisory || null,
        metrics: metricsRows,
        affectedProducts,
        cwes,
        capecs,
        ssvc,
        references,
        changeHistory,
        workarounds,
        solutions
      };

      return sendJson(res, enhancedCveData);
    }

    // --- Vendors Typeahead ---
    if (req.method === 'GET' && pathname === '/api/vendors') {
      const q = url.searchParams.get('q') || '';
      if (q.length > 100) {
        return sendError(res, 'Search query too long (max 100 characters)', 400);
      }

      const rawLimit = parseInt(url.searchParams.get('limit'));
      const limit = isNaN(rawLimit) ? 20 : Math.min(Math.max(rawLimit, 1), 100);

      // Extract distinct vendors from the denormalized cve_products table
      let query, params;
      if (q) {
        query = `
          SELECT vendor, COUNT(DISTINCT cve_id) as count
          FROM cve_products
          WHERE vendor ILIKE $1
          GROUP BY vendor
          ORDER BY count DESC
          LIMIT $2
        `;
        params = [`%${q}%`, limit];
      } else {
        // No search - return top vendors by count
        query = `
          SELECT vendor, COUNT(DISTINCT cve_id) as count
          FROM cve_products
          GROUP BY vendor
          ORDER BY count DESC
          LIMIT $1
        `;
        params = [limit];
      }

      const rows = await db.all(query, ...params);
      return sendJson(res, rows.filter(r => r.vendor && r.vendor !== 'n/a'));
    }

    // --- Products Typeahead ---
    if (req.method === 'GET' && pathname === '/api/products') {
      const q = url.searchParams.get('q') || '';
      const vendor = url.searchParams.get('vendor') || '';

      if (q.length > 100) {
        return sendError(res, 'Search query too long (max 100 characters)', 400);
      }
      if (vendor.length > 200) {
        return sendError(res, 'Vendor name too long (max 200 characters)', 400);
      }

      const rawLimit = parseInt(url.searchParams.get('limit'));
      const limit = isNaN(rawLimit) ? 20 : Math.min(Math.max(rawLimit, 1), 100);

      // Build query with optional vendor and product filters
      const conditions = [];
      const params = [];
      let paramIndex = 1;

      if (q) {
        conditions.push(`product ILIKE $${paramIndex}`);
        params.push(`%${q}%`);
        paramIndex++;
      }
      if (vendor) {
        conditions.push(`vendor = $${paramIndex}`);
        params.push(vendor);
        paramIndex++;
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const query = `
        SELECT
          product,
          vendor,
          COUNT(DISTINCT cve_id) as count
        FROM cve_products
        ${whereClause}
        GROUP BY product, vendor
        ORDER BY count DESC
        LIMIT $${paramIndex}
      `;
      params.push(limit);

      const rows = await db.all(query, ...params);
      return sendJson(res, rows.filter(r => r.product && r.product !== 'n/a'));
    }

    // --- Health & Status ---
    if (req.method === 'GET' && pathname === '/api/health') {
      try {
        // CVE count in database
        const countRow = await db.get('SELECT COUNT(*) as count FROM cves');
        const cveCount = countRow?.count || 0;

        // Estimate repo CVE count (count JSON files in cves/ directory)
        let repoFileCount = null;
        const repoDir = path.join(process.cwd(), 'data', 'cvelistV5', 'cves');
        if (fs.existsSync(repoDir)) {
          // Use a quick approximation - count directories at year level and estimate
          try {
            const years = fs.readdirSync(repoDir).filter(d => /^\d{4}$/.test(d));
            let count = 0;
            for (const year of years) {
              const yearDir = path.join(repoDir, year);
              const subdirs = fs.readdirSync(yearDir);
              for (const subdir of subdirs) {
                const files = fs.readdirSync(path.join(yearDir, subdir));
                count += files.filter(f => f.endsWith('.json') && !f.includes('delta')).length;
              }
            }
            repoFileCount = count;
          } catch {
            // Fallback - directory structure different than expected
          }
        }

        // System metadata
        const metadata = {};
        try {
          const rows = await db.all('SELECT key, value FROM system_metadata');
          for (const row of rows) {
            metadata[row.key] = row.value;
          }
        } catch {
          // Table might not exist
        }

        // Last successful ingestion
        const lastJob = await db.get(`
          SELECT id, start_time, end_time, status, items_processed, items_added, items_updated, error
          FROM job_runs
          WHERE status IN ('COMPLETED', 'FAILED')
          ORDER BY end_time DESC
          LIMIT 1
        `);

        // Running job (if any)
        const runningJob = await db.get(`
          SELECT id, start_time, items_processed, progress_percent, current_phase
          FROM job_runs
          WHERE status = 'RUNNING'
          LIMIT 1
        `);

        // Calculate completeness
        const completeness = repoFileCount ? Math.round((cveCount / repoFileCount) * 100) : null;

        return sendJson(res, {
          database: {
            cveCount,
            repoFileCount,
            completeness: completeness ? `${completeness}%` : 'unknown',
            missingCves: repoFileCount ? repoFileCount - cveCount : null
          },
          tracking: {
            lastCommit: metadata.cvelist_commit || null,
            lastCommitShort: metadata.cvelist_commit?.substring(0, 8) || null
          },
          ingestion: {
            lastJob: lastJob ? {
              id: lastJob.id,
              status: lastJob.status,
              startTime: lastJob.start_time,
              endTime: lastJob.end_time,
              itemsProcessed: lastJob.items_processed,
              itemsAdded: lastJob.items_added,
              itemsUpdated: lastJob.items_updated,
              error: lastJob.error
            } : null,
            runningJob: runningJob ? {
              id: runningJob.id,
              startTime: runningJob.start_time,
              itemsProcessed: runningJob.items_processed,
              progressPercent: runningJob.progress_percent,
              currentPhase: runningJob.current_phase
            } : null
          },
          status: cveCount > 0 ? (completeness && completeness >= 95 ? 'healthy' : 'incomplete') : 'empty'
        });
      } catch (err) {
        return sendError(res, 'Failed to get health status: ' + err.message, 500);
      }
    }

    // --- Jobs ---
    if (req.method === 'GET' && pathname === '/api/jobs') {
      const rows = await db.all('SELECT * FROM job_runs ORDER BY start_time DESC LIMIT 50');
      const jobs = rows.map(r => ({
        id: r.id,
        startTime: r.start_time,
        endTime: r.end_time,
        status: r.status,
        itemsProcessed: r.items_processed,
        progressPercent: r.progress_percent || 0,
        itemsAdded: r.items_added || 0,
        itemsUpdated: r.items_updated || 0,
        itemsUnchanged: r.items_unchanged || 0,
        currentPhase: r.current_phase,
        lastHeartbeat: r.last_heartbeat,
        totalFiles: r.total_files,
        error: r.error
      }));
      return sendJson(res, jobs);
    }

    // Cancel a job
    const jobCancelMatch = pathname.match(/^\/api\/jobs\/(\d+)\/cancel$/);
    if (req.method === 'POST' && jobCancelMatch) {
      const jobId = parseInt(jobCancelMatch[1]);
      await nvd.cancelJob(jobId);
      return sendJson(res, { status: 'Cancellation requested', jobId });
    }

    // Get job logs
    const jobLogsMatch = pathname.match(/^\/api\/jobs\/(\d+)\/logs$/);
    if (req.method === 'GET' && jobLogsMatch) {
      const jobId = parseInt(jobLogsMatch[1]);
      const logs = await db.all('SELECT id, timestamp, level, message, metadata FROM job_logs WHERE job_id = $1 ORDER BY id', jobId);
      return sendJson(res, logs.map(l => ({
        id: l.id,
        timestamp: l.timestamp,
        level: l.level,
        message: l.message,
        metadata: l.metadata ? JSON.parse(l.metadata) : null
      })));
    }

    // SSE log streaming
    const jobLogsStreamMatch = pathname.match(/^\/api\/jobs\/(\d+)\/logs\/stream$/);
    if (req.method === 'GET' && jobLogsStreamMatch) {
      const jobId = parseInt(jobLogsStreamMatch[1]);
      const clientId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
      });

      // Send existing logs first
      const existingLogs = await db.all('SELECT id, timestamp, level, message, metadata FROM job_logs WHERE job_id = $1 ORDER BY id', jobId);
      for (const log of existingLogs) {
        const data = {
          id: log.id,
          timestamp: log.timestamp,
          level: log.level,
          message: log.message,
          metadata: log.metadata ? JSON.parse(log.metadata) : null
        };
        res.write(`data: ${JSON.stringify(data)}\n\n`);
      }

      // Register for new logs
      nvd.registerSseClient(clientId, res, jobId);

      // Handle connection close
      req.on('close', () => {
        nvd.unregisterSseClient(clientId);
      });

      // Keep connection open - don't call sendJson or end
      return;
    }

    // --- Watchlists ---
    if (pathname === '/api/watchlists') {
      if (req.method === 'GET') {
        const rows = await db.all('SELECT * FROM watchlists ORDER BY id DESC');
        const watchlists = rows.map(r => ({
          id: r.id.toString(),
          name: r.name,
          query: JSON.parse(r.query_json),
          enabled: !!r.enabled,
          lastRun: r.last_run,
          matchCount: r.match_count
        }));
        return sendJson(res, watchlists);
      }

      if (req.method === 'POST') {
        const body = await readBody(req);
        const validationError = validateWatchlistBody(body);
        if (validationError) {
          return sendError(res, validationError.error, 400);
        }
        // DuckDB: Use RETURNING to get the inserted ID
        const result = await db.get(
          'INSERT INTO watchlists (name, query_json, enabled) VALUES ($1, $2, $3) RETURNING id',
          body.name.trim(), JSON.stringify(body.query), body.enabled ? 1 : 0
        );
        return sendJson(res, { id: result.id.toString() }, 201);
      }
    }

    const wlMatch = pathname.match(/^\/api\/watchlists\/(\d+)$/);
    if (wlMatch) {
      const id = wlMatch[1];
      if (req.method === 'PUT') {
        const body = await readBody(req);
        const validationError = validateWatchlistBody(body);
        if (validationError) {
          return sendError(res, validationError.error, 400);
        }
        await db.run('UPDATE watchlists SET name = $1, query_json = $2, enabled = $3 WHERE id = $4',
          body.name.trim(), JSON.stringify(body.query), body.enabled ? 1 : 0, id);
        return sendJson(res, { success: true });
      }
      if (req.method === 'DELETE') {
        await db.run('DELETE FROM watchlists WHERE id = $1', id);
        return sendJson(res, { success: true });
      }
    }

    // --- Alerts ---
    if (pathname === '/api/alerts') {
      if (req.method === 'GET') {
        // Support filtering by KEV status and read/unread state
        const kev = url.searchParams.get('kev');
        const unreadOnly = url.searchParams.get('unread') === 'true';

        let query = 'SELECT a.* FROM alerts a';
        const params = [];
        const where = [];

        // Filter by KEV status if requested (DuckDB JSON string comparison)
        if (kev === 'true') {
          query += ' JOIN cves c ON a.cve_id = c.id';
          where.push("(json_extract_string(c.json, '$.kev') = 'true' OR json_extract_string(c.json, '$.kev') = '1')");
        } else if (kev === 'false') {
          query += ' JOIN cves c ON a.cve_id = c.id';
          where.push("(json_extract_string(c.json, '$.kev') IS NULL OR json_extract_string(c.json, '$.kev') = 'false' OR json_extract_string(c.json, '$.kev') = '0')");
        }

        // Filter by read status if requested
        if (unreadOnly) {
          where.push('a.read = 0');
        }

        if (where.length > 0) {
          query += ' WHERE ' + where.join(' AND ');
        }

        query += ' ORDER BY a.created_at DESC';

        const rows = await db.all(query, ...params);
        const alerts = rows.map(r => ({
          id: r.id.toString(),
          cveId: r.cve_id,
          watchlistId: r.watchlist_id ? r.watchlist_id.toString() : null,
          watchlistName: r.watchlist_name,
          type: r.type,
          createdAt: r.created_at,
          read: !!r.read
        }));
        return sendJson(res, alerts);
      }
    }

    const alertReadMatch = pathname.match(/^\/api\/alerts\/(\d+)\/read$/);
    if (req.method === 'PUT' && alertReadMatch) {
      const id = alertReadMatch[1];
      await db.run('UPDATE alerts SET read = 1 WHERE id = $1', id);
      return sendJson(res, { success: true });
    }

    const alertMatch = pathname.match(/^\/api\/alerts\/(\d+)$/);
    if (req.method === 'DELETE' && alertMatch) {
      const id = alertMatch[1];
      await db.run('DELETE FROM alerts WHERE id = $1', id);
      return sendJson(res, { success: true });
    }

    // Bulk operations for alerts
    if (pathname === '/api/alerts/mark-all-read' && req.method === 'PUT') {
      await db.run('UPDATE alerts SET read = 1 WHERE read = 0');
      return sendJson(res, { success: true, updated: 0 });  // DuckDB doesn't return changes count easily
    }

    if (pathname === '/api/alerts/delete-all' && req.method === 'DELETE') {
      await db.run('DELETE FROM alerts');
      return sendJson(res, { success: true, deleted: 0 });  // DuckDB doesn't return changes count easily
    }

    // --- Static File Fallback ---
    // Serve built frontend in production, fall back to dev files otherwise
    if ((req.method === 'GET' || req.method === 'HEAD') && !pathname.startsWith('/api')) {
      const safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');

      // In production, serve from dist/ (built by Vite)
      // In development, serve from public/ or root (for dev files)
      const staticDirs = process.env.NODE_ENV === 'production'
        ? [path.join(process.cwd(), 'dist')]
        : [path.join(process.cwd(), 'public'), process.cwd()];

      for (const dir of staticDirs) {
        const requestPath = pathname === '/' ? '/index.html' : safePath;
        const filePath = path.join(dir, requestPath);

        if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
          const ext = path.extname(filePath);
          const mimeTypes = {
            '.html': 'text/html',
            '.js': 'application/javascript',
            '.css': 'text/css',
            '.json': 'application/json',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon'
          };
          const mime = mimeTypes[ext] || 'application/octet-stream';
          const stats = fs.statSync(filePath);

          res.writeHead(200, { 'Content-Type': mime, 'Content-Length': stats.size });
          if (req.method === 'HEAD') {
            res.end();
          } else {
            fs.createReadStream(filePath).pipe(res);
          }
          return;
        }
      }

      // SPA fallback: serve index.html for unknown routes (client-side routing)
      const indexPaths = process.env.NODE_ENV === 'production'
        ? [path.join(process.cwd(), 'dist', 'index.html')]
        : [path.join(process.cwd(), 'index.html')];

      for (const indexPath of indexPaths) {
        if (fs.existsSync(indexPath)) {
          const stats = fs.statSync(indexPath);
          res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': stats.size });
          if (req.method === 'HEAD') {
            res.end();
          } else {
            fs.createReadStream(indexPath).pipe(res);
          }
          return;
        }
      }
    }

    sendError(res, 'Not Found', 404);

  } catch (err) {
    console.error('Server Error:', err);
    sendError(res, 'Internal Server Error', 500);
  }
}

// Export for testing
export {
  handleRequest,
  sendJson,
  sendError,
  readBody,
  validateWatchlistBody,
  MAX_BODY_SIZE,
  MAX_SEARCH_LENGTH,
  MAX_LIMIT,
  MIN_LIMIT,
  DEFAULT_LIMIT,
  VALID_SEVERITIES,
  MAX_WATCHLIST_NAME_LENGTH
};

// Cleanup orphaned RUNNING jobs on server startup
// These are jobs that were running when the server crashed/restarted
async function cleanupOrphanedJobs() {
  try {
    await ensureDbReady();
    const timestamp = new Date().toISOString();
    await db.run(`
      UPDATE job_runs
      SET status = 'FAILED',
          end_time = $1,
          error = 'Orphaned job - server restarted'
      WHERE status = 'RUNNING'
    `, timestamp);

    console.log(`[Startup] Cleaned up orphaned RUNNING jobs`);
  } catch (err) {
    console.error('[Startup] Error cleaning up orphaned jobs:', err);
  }
}

// Stuck job detector - marks jobs as failed if no heartbeat for 10+ minutes
const STUCK_JOB_THRESHOLD_MS = 10 * 60 * 1000; // 10 minutes
const STUCK_JOB_CHECK_INTERVAL_MS = 60 * 1000; // Check every minute

function startStuckJobDetector() {
  setInterval(async () => {
    try {
      await ensureDbReady();
      const now = Date.now();
      const runningJobs = await db.all(`
        SELECT id, last_heartbeat FROM job_runs
        WHERE status = 'RUNNING'
      `);

      for (const job of runningJobs) {
        if (!job.last_heartbeat) continue;

        const heartbeatTime = new Date(job.last_heartbeat).getTime();
        if (now - heartbeatTime > STUCK_JOB_THRESHOLD_MS) {
          const timestamp = new Date().toISOString();
          await db.run(`
            UPDATE job_runs
            SET status = 'FAILED',
                end_time = $1,
                error = 'Job detected as stuck (no progress for 10+ minutes)'
            WHERE id = $2
          `, timestamp, job.id);
          console.log(`[StuckDetector] Marked job ${job.id} as stuck (last heartbeat: ${job.last_heartbeat})`);
        }
      }
    } catch (err) {
      console.error('[StuckDetector] Error checking for stuck jobs:', err);
    }
  }, STUCK_JOB_CHECK_INTERVAL_MS);
}

// Only start server when run directly (not imported for testing)
// Also allow if running under PM2 (ProcessContainerFork)
const isMainModule = import.meta.url === `file://${process.argv[1]}` || process.argv[1].includes('pm2');

if (isMainModule) {
  // Initialize database and start server
  (async () => {
    try {
      // Wait for database to be ready
      await ensureDbReady();
      console.log('[Startup] Database connection established');

      // Clean up any orphaned jobs from previous server runs
      await cleanupOrphanedJobs();

      const server = http.createServer(handleRequest);
      server.listen(PORT, '127.0.0.1', () => {
        console.log(`Server running at http://127.0.0.1:${PORT}/`);
        console.log('Ingestion endpoint available at POST /api/ingest');

        // Start the stuck job detector
        startStuckJobDetector();
        console.log('Stuck job detector started (checks every 60s, threshold 10min)');
      });
    } catch (err) {
      console.error('[Startup] Failed to start server:', err);
      process.exit(1);
    }
  })();
}
