import db from '../../src/lib/db.js';

describe('Database Module', () => {
    // Clean up test watchlists and alerts after all tests
    afterAll(() => {
        try {
            db.prepare("DELETE FROM alerts WHERE watchlist_name IN ('Test Watchlist', 'Alert Test')").run();
            db.prepare("DELETE FROM watchlists WHERE name IN ('Test Watchlist', 'Alert Test')").run();
        } catch (e) {
            // Ignore cleanup errors
        }
    });

    describe('Connection', () => {
        test('DB connection should be valid and return CVE count', () => {
            const row = db.prepare('SELECT count(*) as cnt FROM cves').get();
            expect(row).toHaveProperty('cnt');
            expect(typeof row.cnt).toBe('number');
        });

        test('should have WAL journal mode', () => {
            const result = db.pragma('journal_mode');
            expect(result[0].journal_mode).toBe('wal');
        });

        test('should have foreign keys enabled', () => {
            const result = db.pragma('foreign_keys');
            expect(result[0].foreign_keys).toBe(1);
        });
    });

    describe('Schema Tables', () => {
        test('cves table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'").get();
            expect(result).toBeDefined();
            expect(result.name).toBe('cves');
        });

        test('metrics table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='metrics'").get();
            expect(result).toBeDefined();
        });

        test('cve_references table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_references'").get();
            expect(result).toBeDefined();
        });

        test('configs table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='configs'").get();
            expect(result).toBeDefined();
        });

        test('job_runs table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='job_runs'").get();
            expect(result).toBeDefined();
        });

        test('cve_changes table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_changes'").get();
            expect(result).toBeDefined();
        });

        test('watchlists table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='watchlists'").get();
            expect(result).toBeDefined();
        });

        test('alerts table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'").get();
            expect(result).toBeDefined();
        });

        test('system_metadata table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='system_metadata'").get();
            expect(result).toBeDefined();
        });
    });

    describe('FTS5 Virtual Table', () => {
        test('cves_fts virtual table should exist', () => {
            const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='cves_fts'").get();
            expect(result).toBeDefined();
        });

        test('cves_fts should support FTS5 operations', () => {
            // Try a simple FTS5 match query
            const result = db.prepare("SELECT * FROM cves_fts WHERE cves_fts MATCH 'test' LIMIT 1").all();
            expect(Array.isArray(result)).toBe(true);
        });

        test('cves_fts should have id, description, and refs columns', () => {
            const tableInfo = db.pragma('table_info(cves_fts)');
            const columnNames = tableInfo.map(col => col.name);

            expect(columnNames).toContain('id');
            expect(columnNames).toContain('description');
            expect(columnNames).toContain('refs');
        });
    });

    describe('Table Columns', () => {
        test('cves table should have expected columns', () => {
            const columns = db.pragma('table_info(cves)');
            const columnNames = columns.map(c => c.name);

            expect(columnNames).toContain('id');
            expect(columnNames).toContain('description');
            expect(columnNames).toContain('published');
            expect(columnNames).toContain('last_modified');
            expect(columnNames).toContain('vuln_status');
            expect(columnNames).toContain('normalized_hash');
            expect(columnNames).toContain('json');
        });

        test('metrics table should have expected columns', () => {
            const columns = db.pragma('table_info(metrics)');
            const columnNames = columns.map(c => c.name);

            expect(columnNames).toContain('cve_id');
            expect(columnNames).toContain('cvss_version');
            expect(columnNames).toContain('score');
            expect(columnNames).toContain('severity');
            expect(columnNames).toContain('vector_string');
        });

        test('watchlists table should have expected columns', () => {
            const columns = db.pragma('table_info(watchlists)');
            const columnNames = columns.map(c => c.name);

            expect(columnNames).toContain('id');
            expect(columnNames).toContain('name');
            expect(columnNames).toContain('query_json');
            expect(columnNames).toContain('enabled');
            expect(columnNames).toContain('last_run');
            expect(columnNames).toContain('match_count');
        });

        test('alerts table should have expected columns', () => {
            const columns = db.pragma('table_info(alerts)');
            const columnNames = columns.map(c => c.name);

            expect(columnNames).toContain('id');
            expect(columnNames).toContain('cve_id');
            expect(columnNames).toContain('watchlist_id');
            expect(columnNames).toContain('watchlist_name');
            expect(columnNames).toContain('type');
            expect(columnNames).toContain('created_at');
            expect(columnNames).toContain('read');
        });
    });

    describe('CRUD Operations', () => {
        const testCveId = 'CVE-TEST-9999';

        afterEach(() => {
            // Cleanup test data
            try {
                db.prepare('DELETE FROM cves_fts WHERE id = ?').run(testCveId);
                db.prepare('DELETE FROM metrics WHERE cve_id = ?').run(testCveId);
                db.prepare('DELETE FROM cves WHERE id = ?').run(testCveId);
            } catch (e) {
                // Ignore cleanup errors
            }
        });

        test('should insert and retrieve CVE', () => {
            const testData = {
                id: testCveId,
                description: 'Test description',
                published: new Date().toISOString(),
                lastModified: new Date().toISOString(),
                json: JSON.stringify({ id: testCveId, test: true })
            };

            db.prepare(`
                INSERT INTO cves (id, description, published, last_modified, json)
                VALUES (?, ?, ?, ?, ?)
            `).run(testData.id, testData.description, testData.published, testData.lastModified, testData.json);

            const result = db.prepare('SELECT * FROM cves WHERE id = ?').get(testCveId);
            expect(result).toBeDefined();
            expect(result.id).toBe(testCveId);
            expect(result.description).toBe('Test description');
        });

        test('should insert and retrieve metrics', () => {
            // First insert CVE
            db.prepare(`
                INSERT INTO cves (id, description, json)
                VALUES (?, ?, ?)
            `).run(testCveId, 'Test', '{}');

            // Insert metric
            db.prepare(`
                INSERT INTO metrics (cve_id, cvss_version, score, severity, vector_string)
                VALUES (?, ?, ?, ?, ?)
            `).run(testCveId, '3.1', 7.5, 'HIGH', 'CVSS:3.1/...');

            const metrics = db.prepare('SELECT * FROM metrics WHERE cve_id = ?').all(testCveId);
            expect(metrics).toHaveLength(1);
            expect(metrics[0].score).toBe(7.5);
        });

        test('should update CVE', () => {
            db.prepare(`
                INSERT INTO cves (id, description, json)
                VALUES (?, ?, ?)
            `).run(testCveId, 'Original', '{}');

            db.prepare(`
                UPDATE cves SET description = ? WHERE id = ?
            `).run('Updated', testCveId);

            const result = db.prepare('SELECT description FROM cves WHERE id = ?').get(testCveId);
            expect(result.description).toBe('Updated');
        });

        test('should delete CVE and cascade to metrics', () => {
            db.prepare(`
                INSERT INTO cves (id, description, json)
                VALUES (?, ?, ?)
            `).run(testCveId, 'Test', '{}');

            db.prepare(`
                INSERT INTO metrics (cve_id, cvss_version, score, severity)
                VALUES (?, ?, ?, ?)
            `).run(testCveId, '3.1', 7.5, 'HIGH');

            db.prepare('DELETE FROM cves WHERE id = ?').run(testCveId);

            const cve = db.prepare('SELECT * FROM cves WHERE id = ?').get(testCveId);
            const metrics = db.prepare('SELECT * FROM metrics WHERE cve_id = ?').all(testCveId);

            expect(cve).toBeUndefined();
            expect(metrics).toHaveLength(0);
        });
    });

    describe('FTS5 Operations', () => {
        const testCveId = 'CVE-FTS-TEST-001';

        afterEach(() => {
            try {
                db.prepare('DELETE FROM cves_fts WHERE id = ?').run(testCveId);
                db.prepare('DELETE FROM cves WHERE id = ?').run(testCveId);
            } catch (e) {
                // Ignore
            }
        });

        test('should insert and search FTS5 entries', () => {
            db.prepare(`
                INSERT INTO cves (id, description, json)
                VALUES (?, ?, ?)
            `).run(testCveId, 'Unique searchable vulnerability', '{}');

            db.prepare(`
                INSERT INTO cves_fts (id, description, refs)
                VALUES (?, ?, ?)
            `).run(testCveId, 'Unique searchable vulnerability', 'https://example.com');

            const results = db.prepare(`
                SELECT * FROM cves_fts WHERE cves_fts MATCH '"searchable"'
            `).all();

            expect(results.length).toBeGreaterThanOrEqual(1);
            expect(results.some(r => r.id === testCveId)).toBe(true);
        });
    });

    describe('Watchlist and Alert Operations', () => {
        let testWatchlistId: number;

        afterEach(() => {
            if (testWatchlistId) {
                try {
                    db.prepare('DELETE FROM alerts WHERE watchlist_id = ?').run(testWatchlistId);
                    db.prepare('DELETE FROM watchlists WHERE id = ?').run(testWatchlistId);
                } catch (e) {
                    // Ignore
                }
            }
        });

        test('should create watchlist', () => {
            const result = db.prepare(`
                INSERT INTO watchlists (name, query_json, enabled)
                VALUES (?, ?, ?)
            `).run('Test Watchlist', '{"text":"test"}', 1);

            testWatchlistId = result.lastInsertRowid as number;
            expect(testWatchlistId).toBeGreaterThan(0);
        });

        test('should create alert for watchlist', () => {
            const wlResult = db.prepare(`
                INSERT INTO watchlists (name, query_json, enabled)
                VALUES (?, ?, ?)
            `).run('Alert Test', '{}', 1);
            testWatchlistId = wlResult.lastInsertRowid as number;

            const alertResult = db.prepare(`
                INSERT INTO alerts (cve_id, watchlist_id, watchlist_name, type, created_at)
                VALUES (?, ?, ?, ?, ?)
            `).run('CVE-2023-0001', testWatchlistId, 'Alert Test', 'NEW_MATCH', new Date().toISOString());

            expect(alertResult.lastInsertRowid).toBeGreaterThan(0);
        });
    });
});
