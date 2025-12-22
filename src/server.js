const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const db = require('./lib/db');
const nvd = require('./lib/ingest/nvd');

const PORT = process.env.PORT || 3000;

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

  const url = new URL(req.url, `http://${req.headers.host}`);
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
      const rows = db.prepare(`
        SELECT json FROM cves 
        ORDER BY last_modified DESC 
        LIMIT 100
      `).all();

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
      return sendJson(res, cves);
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
