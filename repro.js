import db from './src/lib/db.js';

try {
    const search = "2021";
    const limit = 5;
    const offset = 0;

    const query = `
    SELECT c.json, count(*) OVER() as total_count
    FROM cves c
    WHERE c.id IN (SELECT id FROM cves_fts WHERE cves_fts MATCH ?)
    ORDER BY c.published DESC LIMIT ? OFFSET ?
  `;

    const params = [`"cve-2021-11332*"`, limit, offset];
    console.log('Query:', query);
    console.log('Params:', params);

    const rows = db.prepare(query).all(...params);
    console.log('Success!', rows.length, 'rows');
} catch (e) {
    console.error('Error:', e);
}
