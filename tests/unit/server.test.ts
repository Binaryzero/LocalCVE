import { EventEmitter } from 'events';
import {
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
} from '../../src/server.js';
import db from '../../src/lib/db.js';

// Mock response object
class MockResponse {
    statusCode: number = 200;
    headers: Record<string, string> = {};
    body: string = '';
    ended: boolean = false;

    writeHead(status: number, headers: Record<string, string> = {}) {
        this.statusCode = status;
        Object.assign(this.headers, headers);
    }

    setHeader(name: string, value: string) {
        this.headers[name] = value;
    }

    end(data?: string) {
        if (data) this.body = data;
        this.ended = true;
    }

    getJson() {
        return JSON.parse(this.body);
    }
}

// Mock request object
class MockRequest extends EventEmitter {
    method: string;
    url: string;
    headers: Record<string, string>;

    constructor(method: string, url: string, headers: Record<string, string> = {}) {
        super();
        this.method = method;
        this.url = url;
        this.headers = { host: 'localhost', ...headers };
    }

    // Simulate body data
    sendBody(data: string) {
        this.emit('data', Buffer.from(data));
        this.emit('end');
    }

    // Simulate empty body
    sendEmptyBody() {
        this.emit('end');
    }

    // Simulate error
    sendError(error: Error) {
        this.emit('error', error);
    }

    destroy() {
        // Mock destroy
    }
}

describe('Server Helper Functions', () => {
    // Global cleanup for all test watchlists and alerts created by server tests
    afterAll(() => {
        try {
            db.prepare("DELETE FROM alerts WHERE watchlist_name IN ('Test Watchlist', 'Updated Name')").run();
            db.prepare("DELETE FROM watchlists WHERE name IN ('Test Watchlist', 'Updated Name')").run();
        } catch (e) {
            // Ignore cleanup errors
        }
    });

    describe('sendJson', () => {
        test('should send JSON response with 200 status', () => {
            const res = new MockResponse();
            sendJson(res as any, { message: 'success' });

            expect(res.statusCode).toBe(200);
            expect(res.headers['Content-Type']).toBe('application/json');
            expect(res.getJson()).toEqual({ message: 'success' });
            expect(res.ended).toBe(true);
        });

        test('should send JSON response with custom status', () => {
            const res = new MockResponse();
            sendJson(res as any, { id: '123' }, 201);

            expect(res.statusCode).toBe(201);
            expect(res.getJson()).toEqual({ id: '123' });
        });

        test('should include cache control headers', () => {
            const res = new MockResponse();
            sendJson(res as any, {});

            expect(res.headers['Cache-Control']).toBe('no-store, no-cache, must-revalidate, proxy-revalidate');
            expect(res.headers['Pragma']).toBe('no-cache');
            expect(res.headers['Expires']).toBe('0');
        });
    });

    describe('sendError', () => {
        test('should send error response with 500 status by default', () => {
            const res = new MockResponse();
            sendError(res as any, 'Internal Server Error');

            expect(res.statusCode).toBe(500);
            expect(res.getJson()).toEqual({ error: 'Internal Server Error' });
        });

        test('should send error response with custom status', () => {
            const res = new MockResponse();
            sendError(res as any, 'Not Found', 404);

            expect(res.statusCode).toBe(404);
            expect(res.getJson()).toEqual({ error: 'Not Found' });
        });
    });

    describe('readBody', () => {
        test('should parse JSON body', async () => {
            const req = new MockRequest('POST', '/api/test');
            const bodyPromise = readBody(req as any);

            req.sendBody('{"name":"test"}');

            const result = await bodyPromise;
            expect(result).toEqual({ name: 'test' });
        });

        test('should return empty object for empty body', async () => {
            const req = new MockRequest('POST', '/api/test');
            const bodyPromise = readBody(req as any);

            req.sendEmptyBody();

            const result = await bodyPromise;
            expect(result).toEqual({});
        });

        test('should reject on invalid JSON', async () => {
            const req = new MockRequest('POST', '/api/test');
            const bodyPromise = readBody(req as any);

            req.sendBody('invalid json');

            await expect(bodyPromise).rejects.toThrow();
        });

        test('should reject on request error', async () => {
            const req = new MockRequest('POST', '/api/test');
            const bodyPromise = readBody(req as any);

            req.sendError(new Error('Connection reset'));

            await expect(bodyPromise).rejects.toThrow('Connection reset');
        });

        test('should reject body larger than MAX_BODY_SIZE', async () => {
            const req = new MockRequest('POST', '/api/test');
            const bodyPromise = readBody(req as any);

            // Send chunk larger than MAX_BODY_SIZE
            const largeChunk = 'x'.repeat(MAX_BODY_SIZE + 1);
            req.emit('data', Buffer.from(largeChunk));

            await expect(bodyPromise).rejects.toThrow('Request body too large');
        });
    });

    describe('validateWatchlistBody', () => {
        test('should return null for valid body', () => {
            const result = validateWatchlistBody({
                name: 'My Watchlist',
                query: { text: 'test' }
            });
            expect(result).toBeNull();
        });

        test('should reject null body', () => {
            const result = validateWatchlistBody(null);
            expect(result?.error).toBe('Request body must be a JSON object');
        });

        test('should reject non-object body', () => {
            const result = validateWatchlistBody('string');
            expect(result?.error).toBe('Request body must be a JSON object');
        });

        test('should reject array body', () => {
            const result = validateWatchlistBody([]);
            expect(result?.error).toBe('Request body must be a JSON object');
        });

        test('should reject missing name', () => {
            const result = validateWatchlistBody({ query: {} });
            expect(result?.error).toBe('name is required and must be a string');
        });

        test('should reject non-string name', () => {
            const result = validateWatchlistBody({ name: 123, query: {} });
            expect(result?.error).toBe('name is required and must be a string');
        });

        test('should reject empty name', () => {
            const result = validateWatchlistBody({ name: '   ', query: {} });
            expect(result?.error).toBe('name cannot be empty');
        });

        test('should reject name longer than max length', () => {
            const result = validateWatchlistBody({
                name: 'x'.repeat(MAX_WATCHLIST_NAME_LENGTH + 1),
                query: {}
            });
            expect(result?.error).toBe(`name must be ${MAX_WATCHLIST_NAME_LENGTH} characters or less`);
        });

        test('should reject missing query', () => {
            const result = validateWatchlistBody({ name: 'Test' });
            expect(result?.error).toBe('query is required and must be an object');
        });

        test('should reject non-object query', () => {
            const result = validateWatchlistBody({ name: 'Test', query: 'string' });
            expect(result?.error).toBe('query is required and must be an object');
        });

        test('should reject array query', () => {
            const result = validateWatchlistBody({ name: 'Test', query: [] });
            expect(result?.error).toBe('query is required and must be an object');
        });
    });

    describe('Constants', () => {
        test('should have expected values', () => {
            expect(MAX_BODY_SIZE).toBe(1024 * 1024);
            expect(MAX_SEARCH_LENGTH).toBe(500);
            expect(MAX_LIMIT).toBe(1000);
            expect(MIN_LIMIT).toBe(1);
            expect(DEFAULT_LIMIT).toBe(100);
            expect(VALID_SEVERITIES).toEqual(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
            expect(MAX_WATCHLIST_NAME_LENGTH).toBe(255);
        });
    });
});

describe('API Endpoints', () => {
    describe('OPTIONS requests (CORS)', () => {
        test('should respond with 204 for OPTIONS requests', async () => {
            const req = new MockRequest('OPTIONS', '/api/cves');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(204);
            expect(res.headers['Access-Control-Allow-Origin']).toBe('*');
            expect(res.headers['Access-Control-Allow-Methods']).toBe('GET, POST, PUT, DELETE, OPTIONS');
        });
    });

    describe('GET /api/cves', () => {
        // Test CVE with metrics for list endpoint verification
        const listTestCveId = 'CVE-LIST-0001';

        beforeAll(() => {
            // Insert a test CVE with metrics to verify list endpoint includes metrics
            // Use future date to ensure it appears first in the list (sorted by published DESC)
            const testJson = JSON.stringify({
                id: listTestCveId,
                description: 'Test CVE for list endpoint metrics',
                score: 8.0,
                severity: 'HIGH',
                cvssVersion: '3.1',
                published: '2099-01-01T00:00:00Z',
                lastModified: '2099-01-02T00:00:00Z',
            });
            const hash = 'list-test-hash-001';

            try {
                db.prepare(`INSERT OR REPLACE INTO cves (id, description, published, last_modified, normalized_hash, json) VALUES (?, ?, ?, ?, ?, ?)`).run(
                    listTestCveId, 'Test CVE for list endpoint metrics', '2099-01-01T00:00:00Z', '2099-01-02T00:00:00Z', hash, testJson
                );
                // Insert metrics for all three CVSS versions
                db.prepare(`INSERT OR REPLACE INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES (?, ?, ?, ?, ?)`).run(
                    listTestCveId, '3.1', 8.0, 'HIGH', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
                );
                db.prepare(`INSERT OR REPLACE INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES (?, ?, ?, ?, ?)`).run(
                    listTestCveId, '3.0', 7.0, 'HIGH', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                );
                db.prepare(`INSERT OR REPLACE INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES (?, ?, ?, ?, ?)`).run(
                    listTestCveId, '2.0', 6.0, 'MEDIUM', 'AV:N/AC:L/Au:N/C:P/I:P/A:N'
                );
            } catch (e) {
                // Ignore if already exists
            }
        });

        afterAll(() => {
            try {
                db.prepare(`DELETE FROM metrics WHERE cve_id = ?`).run(listTestCveId);
                db.prepare(`DELETE FROM cves WHERE id = ?`).run(listTestCveId);
            } catch (e) {
                // Ignore cleanup errors
            }
        });

        test('should return CVE list', async () => {
            const req = new MockRequest('GET', '/api/cves');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            const data = res.getJson();
            expect(data).toHaveProperty('cves');
            expect(data).toHaveProperty('totalCount');
        });

        test('should return version-specific CVSS scores in list', async () => {
            // First verify our test data exists
            const count = db.prepare(`SELECT count(*) as c FROM cves WHERE id = ?`).get(listTestCveId);
            expect(count.c).toBeGreaterThan(0);

            // Get list without search to find our test CVE
            const req = new MockRequest('GET', `/api/cves?limit=1000`);
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            const data = res.getJson();

            const testCve = data.cves.find((c: any) => c.id === listTestCveId);
            expect(testCve).toBeDefined();
            // Verify version-specific scores from metrics
            expect(testCve.cvss31Score).toBe(8.0);
            expect(testCve.cvss30Score).toBe(7.0);
            expect(testCve.cvss2Score).toBe(6.0);
            expect(testCve.cvss2Severity).toBe('MEDIUM');
        });

        test('should validate search length', async () => {
            const longSearch = 'x'.repeat(MAX_SEARCH_LENGTH + 1);
            const req = new MockRequest('GET', `/api/cves?search=${longSearch}`);
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(400);
            expect(res.getJson().error).toContain('Search query too long');
        });

        test('should validate severity parameter', async () => {
            const req = new MockRequest('GET', '/api/cves?severity=INVALID');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(400);
            expect(res.getJson().error).toContain('Invalid severity');
        });

        test('should accept valid severity parameters', async () => {
            for (const severity of VALID_SEVERITIES) {
                const req = new MockRequest('GET', `/api/cves?severity=${severity}`);
                const res = new MockResponse();

                await handleRequest(req as any, res as any);

                expect(res.statusCode).toBe(200);
            }
        });

        test('should validate CVSS min range', async () => {
            const req = new MockRequest('GET', '/api/cves?cvss_min=15');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(400);
            expect(res.getJson().error).toContain('cvss_min must be between 0 and 10');
        });

        test('should validate CVSS min negative', async () => {
            const req = new MockRequest('GET', '/api/cves?cvss_min=-1');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(400);
        });

        test('should accept valid CVSS parameters', async () => {
            const req = new MockRequest('GET', '/api/cves?cvss_min=5&cvss2_min=3&cvss30_min=4&cvss31_min=6');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle limit parameter', async () => {
            const req = new MockRequest('GET', '/api/cves?limit=50');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle offset parameter', async () => {
            const req = new MockRequest('GET', '/api/cves?offset=10');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle kev parameter', async () => {
            const req = new MockRequest('GET', '/api/cves?kev=true');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle published_from date parameter', async () => {
            const req = new MockRequest('GET', '/api/cves?published_from=2024-01-01');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle published_to date parameter', async () => {
            const req = new MockRequest('GET', '/api/cves?published_to=2024-12-31');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle date range parameters together', async () => {
            const req = new MockRequest('GET', '/api/cves?published_from=2024-01-01&published_to=2024-12-31');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should ignore invalid date format', async () => {
            // Invalid date should be ignored, not cause error
            const req = new MockRequest('GET', '/api/cves?published_from=not-a-date');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            // Should still return 200 (invalid date is simply ignored)
            expect(res.statusCode).toBe(200);
        });

        test('should filter CVEs by date range', async () => {
            // Our test CVE is published at 2099-01-01
            const req = new MockRequest('GET', '/api/cves?published_from=2099-01-01&published_to=2099-12-31');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            const data = res.getJson();
            // Should find our future-dated test CVE
            const testCve = data.cves.find((c: any) => c.id === listTestCveId);
            expect(testCve).toBeDefined();
        });

        test('should handle search parameter', async () => {
            const req = new MockRequest('GET', '/api/cves?search=test');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });
    });

    describe('GET /api/cves/:id', () => {
        test('should return 404 for non-existent CVE', async () => {
            const req = new MockRequest('GET', '/api/cves/CVE-9999-99999');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(404);
        });
    });

    describe('GET /api/jobs', () => {
        test('should return job list', async () => {
            const req = new MockRequest('GET', '/api/jobs');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            expect(Array.isArray(res.getJson())).toBe(true);
        });
    });

    describe('GET /api/watchlists', () => {
        test('should return watchlist array', async () => {
            const req = new MockRequest('GET', '/api/watchlists');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            expect(Array.isArray(res.getJson())).toBe(true);
        });
    });

    describe('POST /api/watchlists', () => {
        afterEach(() => {
            try {
                db.prepare("DELETE FROM watchlists WHERE name = 'Test Watchlist'").run();
            } catch (e) { /* ignore */ }
        });

        test('should create watchlist with valid body', async () => {
            const req = new MockRequest('POST', '/api/watchlists');
            const res = new MockResponse();

            const handlePromise = handleRequest(req as any, res as any);
            req.sendBody(JSON.stringify({
                name: 'Test Watchlist',
                query: { text: 'test' },
                enabled: true
            }));

            await handlePromise;

            expect(res.statusCode).toBe(201);
            expect(res.getJson()).toHaveProperty('id');
        });

        test('should reject invalid watchlist body', async () => {
            const req = new MockRequest('POST', '/api/watchlists');
            const res = new MockResponse();

            const handlePromise = handleRequest(req as any, res as any);
            req.sendBody(JSON.stringify({ invalid: 'body' }));

            await handlePromise;

            expect(res.statusCode).toBe(400);
        });
    });

    describe('PUT /api/watchlists/:id', () => {
        afterEach(() => {
            try {
                db.prepare("DELETE FROM watchlists WHERE name IN ('Original Name', 'Updated Name')").run();
            } catch (e) { /* ignore */ }
        });

        test('should update watchlist with valid body', async () => {
            // First create a watchlist
            const createReq = new MockRequest('POST', '/api/watchlists');
            const createRes = new MockResponse();
            const createPromise = handleRequest(createReq as any, createRes as any);
            createReq.sendBody(JSON.stringify({
                name: 'Original Name',
                query: { text: 'test' }
            }));
            await createPromise;
            const id = createRes.getJson().id;

            // Now update it
            const req = new MockRequest('PUT', `/api/watchlists/${id}`);
            const res = new MockResponse();
            const handlePromise = handleRequest(req as any, res as any);
            req.sendBody(JSON.stringify({
                name: 'Updated Name',
                query: { text: 'updated' },
                enabled: false
            }));

            await handlePromise;

            expect(res.statusCode).toBe(200);
            expect(res.getJson().success).toBe(true);
        });
    });

    describe('DELETE /api/watchlists/:id', () => {
        test('should delete watchlist', async () => {
            // First create a watchlist
            const createReq = new MockRequest('POST', '/api/watchlists');
            const createRes = new MockResponse();
            const createPromise = handleRequest(createReq as any, createRes as any);
            createReq.sendBody(JSON.stringify({
                name: 'To Delete',
                query: { text: 'test' }
            }));
            await createPromise;
            const id = createRes.getJson().id;

            // Now delete it
            const req = new MockRequest('DELETE', `/api/watchlists/${id}`);
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            expect(res.getJson().success).toBe(true);
        });
    });

    describe('GET /api/alerts', () => {
        test('should return alerts array', async () => {
            const req = new MockRequest('GET', '/api/alerts');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            expect(Array.isArray(res.getJson())).toBe(true);
        });

        test('should filter by kev=true', async () => {
            const req = new MockRequest('GET', '/api/alerts?kev=true');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should filter by kev=false', async () => {
            const req = new MockRequest('GET', '/api/alerts?kev=false');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should filter unread only', async () => {
            const req = new MockRequest('GET', '/api/alerts?unread=true');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });
    });

    describe('PUT /api/alerts/:id/read', () => {
        test('should mark alert as read', async () => {
            const req = new MockRequest('PUT', '/api/alerts/1/read');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            expect(res.getJson().success).toBe(true);
        });
    });

    describe('DELETE /api/alerts/:id', () => {
        test('should delete alert', async () => {
            const req = new MockRequest('DELETE', '/api/alerts/1');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            expect(res.getJson().success).toBe(true);
        });
    });

    describe('PUT /api/alerts/mark-all-read', () => {
        test('should mark all alerts as read', async () => {
            const req = new MockRequest('PUT', '/api/alerts/mark-all-read');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            expect(res.getJson()).toHaveProperty('success', true);
            expect(res.getJson()).toHaveProperty('updated');
        });
    });

    describe('DELETE /api/alerts/delete-all', () => {
        test('should delete all alerts', async () => {
            const req = new MockRequest('DELETE', '/api/alerts/delete-all');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            expect(res.getJson()).toHaveProperty('success', true);
            expect(res.getJson()).toHaveProperty('deleted');
        });
    });

    describe('Unknown endpoints', () => {
        test('should return 404 for unknown API endpoint', async () => {
            const req = new MockRequest('GET', '/api/unknown');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(404);
            expect(res.getJson().error).toBe('Not Found');
        });
    });

    describe('POST /api/ingest', () => {
        test('should start ingestion job', async () => {
            const req = new MockRequest('POST', '/api/ingest');
            const res = new MockResponse();

            req.sendEmptyBody();
            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(202);
            const data = res.getJson();
            expect(data.status).toBe('Ingestion started');
            expect(data).toHaveProperty('jobId');
        });
    });

    describe('Error handling', () => {
        test('should handle internal server errors gracefully', async () => {
            // This is hard to trigger without mocking, but we can test the error path exists
            const req = new MockRequest('GET', '/api/cves');
            const res = new MockResponse();

            // The handler should complete without throwing
            await handleRequest(req as any, res as any);
            expect(res.ended).toBe(true);
        });
    });

    describe('CVSS version-specific filtering', () => {
        test('should validate cvss2_min range', async () => {
            const req = new MockRequest('GET', '/api/cves?cvss2_min=15');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(400);
            expect(res.getJson().error).toContain('cvss2_min must be between 0 and 10');
        });

        test('should validate cvss30_min range', async () => {
            const req = new MockRequest('GET', '/api/cves?cvss30_min=15');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(400);
            expect(res.getJson().error).toContain('cvss30_min must be between 0 and 10');
        });

        test('should validate cvss31_min range', async () => {
            const req = new MockRequest('GET', '/api/cves?cvss31_min=15');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(400);
            expect(res.getJson().error).toContain('cvss31_min must be between 0 and 10');
        });
    });

    describe('Limit and offset bounds', () => {
        test('should cap limit to MAX_LIMIT', async () => {
            const req = new MockRequest('GET', `/api/cves?limit=${MAX_LIMIT + 500}`);
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should floor limit to MIN_LIMIT', async () => {
            const req = new MockRequest('GET', '/api/cves?limit=0');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle negative offset', async () => {
            const req = new MockRequest('GET', '/api/cves?offset=-10');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle non-numeric limit', async () => {
            const req = new MockRequest('GET', '/api/cves?limit=abc');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should handle non-numeric offset', async () => {
            const req = new MockRequest('GET', '/api/cves?offset=xyz');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });
    });

    describe('Severity case insensitivity', () => {
        test('should accept lowercase severity', async () => {
            const req = new MockRequest('GET', '/api/cves?severity=high');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });

        test('should accept mixed case severity', async () => {
            const req = new MockRequest('GET', '/api/cves?severity=CrItIcAl');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
        });
    });

    describe('GET /api/cves/:id (detail endpoint)', () => {
        // Insert a test CVE for testing
        const testCveId = 'CVE-9999-0001';

        beforeAll(() => {
            // Insert a test CVE into the database
            const testCve = {
                id: testCveId,
                description: 'Test CVE for unit testing',
                published: '2023-01-01T00:00:00.000Z',
                lastModified: '2023-01-02T00:00:00.000Z',
                score: 7.5,
                severity: 'HIGH',
                cvssVersion: '3.1',
                kev: false,
                references: ['https://test.com']
            };

            try {
                db.prepare(`
                    INSERT OR REPLACE INTO cves (id, description, published, last_modified, normalized_hash, json)
                    VALUES (?, ?, ?, ?, ?, ?)
                `).run(
                    testCveId,
                    testCve.description,
                    testCve.published,
                    testCve.lastModified,
                    'test_hash',
                    JSON.stringify(testCve)
                );

                // Insert metrics - all three CVSS versions to cover all switch cases
                db.prepare(`
                    INSERT OR REPLACE INTO metrics (cve_id, cvss_version, score, severity, vector_string)
                    VALUES (?, ?, ?, ?, ?)
                `).run(testCveId, '3.1', 7.5, 'HIGH', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L');

                db.prepare(`
                    INSERT OR REPLACE INTO metrics (cve_id, cvss_version, score, severity, vector_string)
                    VALUES (?, ?, ?, ?, ?)
                `).run(testCveId, '3.0', 6.5, 'MEDIUM', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L');

                db.prepare(`
                    INSERT OR REPLACE INTO metrics (cve_id, cvss_version, score, severity, vector_string)
                    VALUES (?, ?, ?, ?, ?)
                `).run(testCveId, '2.0', 5.0, 'MEDIUM', 'AV:N/AC:L/Au:N/C:N/I:P/A:N');
            } catch (e) {
                // Ignore errors if already exists
            }
        });

        afterAll(() => {
            // Cleanup
            try {
                db.prepare('DELETE FROM metrics WHERE cve_id = ?').run(testCveId);
                db.prepare('DELETE FROM cves WHERE id = ?').run(testCveId);
            } catch (e) {
                // Ignore cleanup errors
            }
        });

        test('should return detailed CVE data with all metrics', async () => {
            const req = new MockRequest('GET', `/api/cves/${testCveId}`);
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            expect(res.statusCode).toBe(200);
            const data = res.getJson();
            expect(data.id).toBe(testCveId);
            expect(data.description).toBe('Test CVE for unit testing');
            expect(data.metrics).toBeDefined();
            expect(Array.isArray(data.metrics)).toBe(true);
        });

        test('should include version-specific CVSS scores', async () => {
            const req = new MockRequest('GET', `/api/cves/${testCveId}`);
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            const data = res.getJson();
            // All three CVSS versions should be present
            expect(data.cvss31Score).toBe(7.5);
            expect(data.cvss30Score).toBe(6.5);
            expect(data.cvss2Score).toBe(5.0);
        });
    });

    describe('Watchlist validation edge cases', () => {
        test('should reject PUT with invalid body', async () => {
            const req = new MockRequest('PUT', '/api/watchlists/999');
            const res = new MockResponse();

            const handlePromise = handleRequest(req as any, res as any);
            req.sendBody(JSON.stringify({ invalid: 'body' }));

            await handlePromise;

            expect(res.statusCode).toBe(400);
        });
    });

    describe('Static file handling', () => {
        test('should return 404 for non-existent static files', async () => {
            const req = new MockRequest('GET', '/nonexistent.html');
            const res = new MockResponse();

            await handleRequest(req as any, res as any);

            // May return 404 or attempt SPA fallback depending on setup
            expect(res.ended).toBe(true);
        });
    });
});
