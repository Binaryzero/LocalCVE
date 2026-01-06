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

const readBody = (req) => new Promise((resolve, reject) => {
  let body = '';
  req.on('data', chunk => body += chunk);
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
      const search = url.searchParams.get('search') || '';
      const limit = parseInt(url.searchParams.get('limit')) || 100;
      const offset = parseInt(url.searchParams.get('offset')) || 0;
      const severity = url.searchParams.get('severity');
      const cvssMin = parseFloat(url.searchParams.get('cvss_min'));

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

      if (severity || cvssMin) {
        where.push(`c.id IN (SELECT cve_id FROM metrics WHERE 1=1 ${severity ? 'AND severity = ?' : ''} ${cvssMin ? 'AND score >= ?' : ''})`);
        if (severity) params.push(severity.toUpperCase());
        if (cvssMin) params.push(cvssMin);
      }

      if (where.length > 0) {
        query += ` WHERE ` + where.join(' AND ');
      }

      query += ` ORDER BY c.published DESC LIMIT ? OFFSET ? `;
      params.push(limit, offset);

      const rows = db.prepare(query).all(...params);
      const totalCount = rows.length > 0 ? rows[0].total_count : 0;

      const cves = rows.map(r => {
        const data = JSON.parse(r.json);
        return {
          id: data.id,
          description: data.description,
          cvssV3Score: data.score,
          cvssV3Severity: data.severity,
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
      return sendJson(res, JSON.parse(row.json));
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
        const info = db.prepare('INSERT INTO watchlists (name, query_json, enabled) VALUES (?, ?, ?)')
          .run(body.name, JSON.stringify(body.query), body.enabled ? 1 : 0);
        return sendJson(res, { id: info.lastInsertRowid.toString() }, 201);
      }
    }

    const wlMatch = pathname.match(/^\/api\/watchlists\/(\d+)$/);
    if (wlMatch) {
      const id = wlMatch[1];
      if (req.method === 'PUT') {
        const body = await readBody(req);
        db.prepare('UPDATE watchlists SET name = ?, query_json = ?, enabled = ? WHERE id = ?')
          .run(body.name, JSON.stringify(body.query), body.enabled ? 1 : 0, id);
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
        const rows = db.prepare('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100').all();
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

    // --- Static File Fallback ---
    if (req.method === 'GET' && !pathname.startsWith('/api')) {
      const safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
      const filePath = path.join(process.cwd(), 'public', safePath);

      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath);
        const mime = ext === '.html' ? 'text/html' :
          ext === '.js' ? 'application/javascript' :
            ext === '.css' ? 'text/css' : 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': mime });
        fs.createReadStream(filePath).pipe(res);
        return;
      }

      const indexHtml = path.join(process.cwd(), 'index.html');
      if (fs.existsSync(indexHtml)) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        fs.createReadStream(indexHtml).pipe(res);
        return;
      }
    }

    sendError(res, 'Not Found', 404);

  } catch (err) {
    console.error('Server Error:', err);
    sendError(res, 'Internal Server Error', 500);
  }
}

const server = http.createServer(handleRequest);

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Server running at http://127.0.0.1:${PORT}/`);
  console.log('Ingestion endpoint available at POST /api/ingest');
});
