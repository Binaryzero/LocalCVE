import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';
import db from './lib/db.js';
import * as nvd from './lib/ingest/nvd.js';

const PORT = process.env.PORT || 17920;

const sendJson = (res, data, status = 200) => {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });
  res.end(JSON.stringify(data));
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

  try {
    // --- Ingestion ---
    if (req.method === 'POST' && pathname === '/api/ingest') {
      console.log('[API] Triggering ingestion job...');
      try {
        const jobId = nvd.run(); // Returns jobId synchronously now
        return sendJson(res, { status: 'Ingestion started', jobId }, 202);
      } catch (e) {
        console.error("Failed to start ingestion job:", e);
        return sendError(res, 'Failed to start ingestion job: ' + e.message, 500);
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

      // Build base query to get CVEs with their JSON data
      let query = `
        SELECT c.json, count(*) OVER() as total_count
        FROM cves c
      `;
      const params = [];
      const where = [];

      if (search) {
        where.push(`c.id IN (SELECT id FROM cves_fts WHERE cves_fts MATCH ?)`);
        // Escape double quotes and wrapping in quotes to ensure phrase search
        // This avoids FTS5 syntax errors with hyphens/special chars
        const term = search.replace(/"/g, '""');
        params.push(`"${term}*"`);
      }

      // Handle filtering by severity or minimum CVSS scores
      const metricConditions = [];
      if (severity) {
        metricConditions.push('severity = ?');
        params.push(severity); // Already uppercased during validation
      }
      if (cvssMin) {
        metricConditions.push('score >= ?');
        params.push(cvssMin);
      }

      // Add version-specific filtering
      if (cvss2Min) {
        metricConditions.push('(cvss_version = ? AND score >= ?)');
        params.push('2.0', cvss2Min);
      }
      if (cvss30Min) {
        metricConditions.push('(cvss_version = ? AND score >= ?)');
        params.push('3.0', cvss30Min);
      }
      if (cvss31Min) {
        metricConditions.push('(cvss_version = ? AND score >= ?)');
        params.push('3.1', cvss31Min);
      }

      if (metricConditions.length > 0) {
        where.push(`c.id IN (SELECT cve_id FROM metrics WHERE ${metricConditions.join(' OR ')})`);
      }

      // KEV filtering
      if (kev === 'true') {
        where.push("json_extract(c.json, '$.kev') = 1");
      }

      if (where.length > 0) {
        query += ` WHERE ` + where.join(' AND ');
      }

      query += ` ORDER BY c.published DESC LIMIT ? OFFSET ? `;
      params.push(limit, offset);

      const rows = db.prepare(query).all(...params);
      const totalCount = rows.length > 0 ? rows[0].total_count : 0;

      // Get all metrics for the CVEs in this result set
      const cveIds = rows.map(r => {
        const data = JSON.parse(r.json);
        return data.id;
      });

      const metricsMap = new Map();
      if (cveIds.length > 0) {
        // Create placeholders for the IN clause
        const placeholders = cveIds.map(() => '?').join(',');
        const metricsQuery = `SELECT cve_id, cvss_version, score, severity, vector_string FROM metrics WHERE cve_id IN (${placeholders})`;
        const metricsRows = db.prepare(metricsQuery).all(...cveIds);

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
      const row = db.prepare('SELECT json FROM cves WHERE id = ?').get(id);
      if (!row) return sendJson(res, { error: 'Not found' }, 404);

      // Get all metrics for this CVE
      const metricsRows = db.prepare('SELECT cvss_version, score, severity, vector_string FROM metrics WHERE cve_id = ?').all(id);

      // Parse the base CVE data
      const cveData = JSON.parse(row.json);

      // Add version-specific metrics to the response
      let cvss2Score = null, cvss2Severity = null;
      let cvss30Score = null, cvss30Severity = null;
      let cvss31Score = null, cvss31Severity = null;

      for (const metric of metricsRows) {
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

      // Add the version-specific fields to the response
      const enhancedCveData = {
        ...cveData,
        // Version-specific scores
        cvss2Score,
        cvss2Severity,
        cvss30Score,
        cvss30Severity,
        cvss31Score,
        cvss31Severity,
        // Metrics details
        metrics: metricsRows
      };

      return sendJson(res, enhancedCveData);
    }

    // --- Jobs ---
    if (req.method === 'GET' && pathname === '/api/jobs') {
      const rows = db.prepare('SELECT * FROM job_runs ORDER BY start_time DESC LIMIT 50').all();
      const jobs = rows.map(r => ({
        id: r.id,
        startTime: r.start_time,
        endTime: r.end_time,
        status: r.status,
        itemsProcessed: r.items_processed,
        error: r.error
      }));
      return sendJson(res, jobs);
    }

    // --- Watchlists ---
    if (pathname === '/api/watchlists') {
      if (req.method === 'GET') {
        const rows = db.prepare('SELECT * FROM watchlists ORDER BY id DESC').all();
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
        const info = db.prepare('INSERT INTO watchlists (name, query_json, enabled) VALUES (?, ?, ?)')
          .run(body.name.trim(), JSON.stringify(body.query), body.enabled ? 1 : 0);
        return sendJson(res, { id: info.lastInsertRowid.toString() }, 201);
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
        db.prepare('UPDATE watchlists SET name = ?, query_json = ?, enabled = ? WHERE id = ?')
          .run(body.name.trim(), JSON.stringify(body.query), body.enabled ? 1 : 0, id);
        return sendJson(res, { success: true });
      }
      if (req.method === 'DELETE') {
        db.prepare('DELETE FROM watchlists WHERE id = ?').run(id);
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

        // Filter by KEV status if requested
        if (kev === 'true') {
          query += ' JOIN cves c ON a.cve_id = c.id';
          where.push("json_extract(c.json, '$.kev') = 1");
        } else if (kev === 'false') {
          query += ' JOIN cves c ON a.cve_id = c.id';
          where.push("(json_extract(c.json, '$.kev') IS NULL OR json_extract(c.json, '$.kev') = 0)");
        }

        // Filter by read status if requested
        if (unreadOnly) {
          where.push('a.read = 0');
        }

        if (where.length > 0) {
          query += ' WHERE ' + where.join(' AND ');
        }

        query += ' ORDER BY a.created_at DESC';

        const rows = db.prepare(query).all(...params);
        const alerts = rows.map(r => ({
          id: r.id.toString(),
          cveId: r.cve_id,
          watchlistId: r.watchlist_id.toString(),
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
      db.prepare('UPDATE alerts SET read = 1 WHERE id = ?').run(id);
      return sendJson(res, { success: true });
    }

    const alertMatch = pathname.match(/^\/api\/alerts\/(\d+)$/);
    if (req.method === 'DELETE' && alertMatch) {
      const id = alertMatch[1];
      db.prepare('DELETE FROM alerts WHERE id = ?').run(id);
      return sendJson(res, { success: true });
    }

    // Bulk operations for alerts
    if (pathname === '/api/alerts/mark-all-read' && req.method === 'PUT') {
      const result = db.prepare('UPDATE alerts SET read = 1 WHERE read = 0').run();
      return sendJson(res, { success: true, updated: result.changes });
    }

    if (pathname === '/api/alerts/delete-all' && req.method === 'DELETE') {
      const result = db.prepare('DELETE FROM alerts').run();
      return sendJson(res, { success: true, deleted: result.changes });
    }

    // --- Static File Fallback ---
    // Serve built frontend in production, fall back to dev files otherwise
    if (req.method === 'GET' && !pathname.startsWith('/api')) {
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

          res.writeHead(200, { 'Content-Type': mime });
          fs.createReadStream(filePath).pipe(res);
          return;
        }
      }

      // SPA fallback: serve index.html for unknown routes (client-side routing)
      const indexPaths = process.env.NODE_ENV === 'production'
        ? [path.join(process.cwd(), 'dist', 'index.html')]
        : [path.join(process.cwd(), 'index.html')];

      for (const indexPath of indexPaths) {
        if (fs.existsSync(indexPath)) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          fs.createReadStream(indexPath).pipe(res);
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

// Only start server when run directly (not imported for testing)
// Also allow if running under PM2 (ProcessContainerFork)
const isMainModule = import.meta.url === `file://${process.argv[1]}` || process.argv[1].includes('pm2');

if (isMainModule) {
  const server = http.createServer(handleRequest);
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`Server running at http://127.0.0.1:${PORT}/`);
    console.log('Ingestion endpoint available at POST /api/ingest');
  });
}
