import db from '../../src/lib/db.js';

test('DB connection should be valid and return CVE count', () => {
    const row = db.prepare('SELECT count(*) as cnt FROM cves').get();
    expect(row).toHaveProperty('cnt');
    expect(typeof row.cnt).toBe('number');
});
