import {
    normalizeCve5,
    computeHash,
    getDiff,
    ensureDir,
    getTimestamp,
    walk,
    getChangedFiles
} from '../../src/lib/ingest/nvd.js';
import getDb, { initPromise } from '../../src/lib/db.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Wait for database initialization before all tests
let db: any;

beforeAll(async () => {
    await initPromise;
    db = getDb();
});

// Global cleanup for all NVD test watchlists - runs after all tests in this file
afterAll(async () => {
    try {
        // Clean up all test watchlists created by NVD tests
        await db.run("DELETE FROM alerts WHERE watchlist_name LIKE '%Test%' OR watchlist_name LIKE 'BatchTest%' OR watchlist_name LIKE 'RefreshTest%' OR watchlist_name LIKE 'StmtTest%' OR watchlist_name LIKE 'Ingest Test%' OR watchlist_name LIKE 'Alert Gen%'");
        await db.run("DELETE FROM watchlists WHERE name LIKE '%Test%' OR name LIKE 'BatchTest%' OR name LIKE 'RefreshTest%' OR name LIKE 'StmtTest%' OR name LIKE 'Ingest Test%' OR name LIKE 'Alert Gen%' OR name LIKE 'Updated Name'");
        // Clean up test CVEs
        await db.run("DELETE FROM cve_references WHERE cve_id LIKE 'CVE-BATCH-TEST%'");
        await db.run("DELETE FROM configs WHERE cve_id LIKE 'CVE-BATCH-TEST%'");
        await db.run("DELETE FROM metrics WHERE cve_id LIKE 'CVE-BATCH-TEST%'");
        await db.run("DELETE FROM cve_changes WHERE cve_id LIKE 'CVE-BATCH-TEST%'");
        await db.run("DELETE FROM cve_cwes WHERE cve_id LIKE 'CVE-BATCH-TEST%'");
        await db.run("DELETE FROM cve_capec WHERE cve_id LIKE 'CVE-BATCH-TEST%'");
        await db.run("DELETE FROM cve_ssvc WHERE cve_id LIKE 'CVE-BATCH-TEST%'");
        await db.run("DELETE FROM cves WHERE id LIKE 'CVE-BATCH-TEST%'");
    } catch (e) {
        // Ignore cleanup errors
    }
});

describe('CVE Normalization', () => {
    // Helper to create mock CVE JSON 5.0 data
    const createMockCve = (overrides: any = {}) => ({
        cveMetadata: {
            cveId: 'CVE-2022-1234',
            state: 'PUBLISHED',
            datePublished: '2022-01-01T00:00:00.000Z',
            dateUpdated: '2022-01-02T00:00:00.000Z',
            ...overrides.cveMetadata
        },
        containers: {
            cna: {
                descriptions: [
                    { lang: 'en', value: 'Test vulnerability description' }
                ],
                metrics: [],
                references: [{ url: 'https://example.com' }],
                affected: [],
                ...overrides.cna
            }
        }
    });

    describe('Basic metadata extraction', () => {
        test('should extract CVE ID', () => {
            const result = normalizeCve5(createMockCve());
            expect(result.id).toBe('CVE-2022-1234');
        });

        test('should extract vulnerability status', () => {
            const result = normalizeCve5(createMockCve());
            expect(result.vulnStatus).toBe('PUBLISHED');
        });

        test('should extract and format published date', () => {
            const result = normalizeCve5(createMockCve());
            expect(result.published).toBe('2022-01-01T00:00:00.000Z');
        });

        test('should extract and format lastModified date', () => {
            const result = normalizeCve5(createMockCve());
            expect(result.lastModified).toBe('2022-01-02T00:00:00.000Z');
        });

        test('should handle missing datePublished', () => {
            const mockCve = createMockCve();
            mockCve.cveMetadata.datePublished = null;
            const result = normalizeCve5(mockCve);
            expect(result.published).toBeNull();
        });

        test('should handle missing dateUpdated', () => {
            const mockCve = createMockCve();
            mockCve.cveMetadata.dateUpdated = null;
            const result = normalizeCve5(mockCve);
            expect(result.lastModified).toBeNull();
        });
    });

    describe('Description extraction', () => {
        test('should extract English description', () => {
            const result = normalizeCve5(createMockCve());
            expect(result.description).toBe('Test vulnerability description');
        });

        test('should prefer English description over others', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.descriptions = [
                { lang: 'es', value: 'Spanish description' },
                { lang: 'en', value: 'English description' }
            ];
            const result = normalizeCve5(mockCve);
            expect(result.description).toBe('English description');
        });

        test('should fall back to first description if no English', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.descriptions = [
                { lang: 'es', value: 'Spanish description' },
                { lang: 'fr', value: 'French description' }
            ];
            const result = normalizeCve5(mockCve);
            expect(result.description).toBe('Spanish description');
        });

        test('should handle missing descriptions', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.descriptions = undefined;
            const result = normalizeCve5(mockCve);
            expect(result.description).toBe('No description available');
        });

        test('should handle empty descriptions array', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.descriptions = [];
            const result = normalizeCve5(mockCve);
            expect(result.description).toBe('No description available');
        });
    });

    describe('CVSS v3.1 metrics', () => {
        test('should extract CVSS v3.1 scores', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [{
                cvssV3_1: {
                    baseScore: 7.5,
                    baseSeverity: 'HIGH',
                    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                }
            }];
            const result = normalizeCve5(mockCve);

            expect(result.cvss31Score).toBe(7.5);
            expect(result.cvss31Severity).toBe('HIGH');
            expect(result.cvssVersion).toBe('3.1');
            expect(result.score).toBe(7.5);
            expect(result.severity).toBe('HIGH');
        });

        test('should include v3.1 in allMetrics array', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [{
                cvssV3_1: {
                    baseScore: 7.5,
                    baseSeverity: 'HIGH',
                    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                }
            }];
            const result = normalizeCve5(mockCve);

            expect(result.allMetrics).toHaveLength(1);
            expect(result.allMetrics[0].version).toBe('3.1');
            expect(result.allMetrics[0].score).toBe(7.5);
        });
    });

    describe('CVSS v3.0 metrics', () => {
        test('should extract CVSS v3.0 scores', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [{
                cvssV3_0: {
                    baseScore: 6.5,
                    baseSeverity: 'MEDIUM',
                    vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                }
            }];
            const result = normalizeCve5(mockCve);

            expect(result.cvss30Score).toBe(6.5);
            expect(result.cvss30Severity).toBe('MEDIUM');
            expect(result.cvssVersion).toBe('3.0');
            expect(result.score).toBe(6.5);
        });

        test('should set v3.0 as primary when v3.1 not present', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [{
                cvssV3_0: {
                    baseScore: 6.5,
                    baseSeverity: 'MEDIUM',
                    vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                }
            }];
            const result = normalizeCve5(mockCve);

            expect(result.cvssVersion).toBe('3.0');
            expect(result.score).toBe(6.5);
        });
    });

    describe('CVSS v2.0 metrics', () => {
        test('should extract CVSS v2.0 scores', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [{
                cvssV2_0: {
                    baseScore: 5.0,
                    baseSeverity: 'MEDIUM',
                    vectorString: 'AV:N/AC:L/Au:N/C:N/I:P/A:N'
                }
            }];
            const result = normalizeCve5(mockCve);

            expect(result.cvss2Score).toBe(5.0);
            expect(result.cvss2Severity).toBe('MEDIUM');
            expect(result.cvssVersion).toBe('2.0');
            expect(result.score).toBe(5.0);
        });

        test('should default severity to UNKNOWN if missing', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [{
                cvssV2_0: {
                    baseScore: 5.0,
                    vectorString: 'AV:N/AC:L/Au:N/C:N/I:P/A:N'
                    // Missing baseSeverity
                }
            }];
            const result = normalizeCve5(mockCve);

            expect(result.cvss2Severity).toBe('UNKNOWN');
        });
    });

    describe('Multi-version CVSS metrics', () => {
        test('should collect all CVSS versions', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [
                {
                    cvssV3_1: {
                        baseScore: 7.5,
                        baseSeverity: 'HIGH',
                        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    }
                },
                {
                    cvssV3_0: {
                        baseScore: 6.5,
                        baseSeverity: 'MEDIUM',
                        vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    }
                },
                {
                    cvssV2_0: {
                        baseScore: 5.0,
                        baseSeverity: 'MEDIUM',
                        vectorString: 'AV:N/AC:L/Au:N/C:N/I:P/A:N'
                    }
                }
            ];
            const result = normalizeCve5(mockCve);

            // Check all versions are collected
            expect(result.allMetrics).toHaveLength(3);

            // Check version-specific fields
            expect(result.cvss2Score).toBe(5.0);
            expect(result.cvss30Score).toBe(6.5);
            expect(result.cvss31Score).toBe(7.5);

            // Check primary score is highest priority (3.1)
            expect(result.cvssVersion).toBe('3.1');
            expect(result.score).toBe(7.5);
        });

        test('should use first encountered v3.x as primary (v3.1 first)', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [
                {
                    cvssV3_1: {
                        baseScore: 7.5,
                        baseSeverity: 'HIGH',
                        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    }
                },
                {
                    cvssV3_0: {
                        baseScore: 9.0,
                        baseSeverity: 'CRITICAL',
                        vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
                    }
                }
            ];
            const result = normalizeCve5(mockCve);

            // First v3.1 becomes primary since it's processed first
            expect(result.cvssVersion).toBe('3.1');
            expect(result.score).toBe(7.5);
        });

        test('should prefer v3.1 over v3.0 based on version priority', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [
                {
                    cvssV3_0: {
                        baseScore: 9.0,
                        baseSeverity: 'CRITICAL',
                        vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
                    }
                },
                {
                    cvssV3_1: {
                        baseScore: 7.5,
                        baseSeverity: 'HIGH',
                        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    }
                }
            ];
            const result = normalizeCve5(mockCve);

            // v3.1 is preferred over v3.0 due to version priority (4.0 > 3.1 > 3.0 > 2.0)
            expect(result.cvssVersion).toBe('3.1');
            expect(result.score).toBe(7.5);
        });

        test('should upgrade from v2.0 to v3.0 as primary when v3.0 is found', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [
                {
                    cvssV2_0: {
                        baseScore: 5.0,
                        baseSeverity: 'MEDIUM',
                        vectorString: 'AV:N/AC:L/Au:N/C:N/I:P/A:N'
                    }
                },
                {
                    cvssV3_0: {
                        baseScore: 6.5,
                        baseSeverity: 'MEDIUM',
                        vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    }
                }
            ];
            const result = normalizeCve5(mockCve);

            // v3.0 should override v2.0 as primary
            expect(result.cvssVersion).toBe('3.0');
            expect(result.score).toBe(6.5);
        });

        test('should handle CVE with only one CVSS version', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [{
                cvssV2_0: {
                    baseScore: 5.0,
                    baseSeverity: 'MEDIUM',
                    vectorString: 'AV:N/AC:L/Au:N/C:N/I:P/A:N'
                }
            }];
            const result = normalizeCve5(mockCve);

            expect(result.allMetrics).toHaveLength(1);
            expect(result.cvss2Score).toBe(5.0);
            expect(result.cvss30Score).toBeNull();
            expect(result.cvss31Score).toBeNull();
            expect(result.cvssVersion).toBe('2.0');
        });
    });

    describe('No metrics', () => {
        test('should handle CVE with no metrics', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = [];
            const result = normalizeCve5(mockCve);

            expect(result.allMetrics).toHaveLength(0);
            expect(result.cvssVersion).toBeNull();
            expect(result.score).toBeNull();
            expect(result.severity).toBeNull();
            expect(result.cvss2Score).toBeNull();
            expect(result.cvss30Score).toBeNull();
            expect(result.cvss31Score).toBeNull();
        });

        test('should handle CVE with undefined metrics', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.metrics = undefined;
            const result = normalizeCve5(mockCve);

            expect(result.allMetrics).toHaveLength(0);
            expect(result.score).toBeNull();
        });
    });

    describe('References extraction', () => {
        test('should extract and sort references with tags', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.references = [
                { url: 'https://zebra.com', tags: ['vendor-advisory'] },
                { url: 'https://apple.com' },
                { url: 'https://mango.com', tags: ['patch', 'exploit'] }
            ];
            const result = normalizeCve5(mockCve);

            // References should be sorted by URL and include tags
            expect(result.references).toEqual([
                { url: 'https://apple.com', tags: [] },
                { url: 'https://mango.com', tags: ['patch', 'exploit'] },
                { url: 'https://zebra.com', tags: ['vendor-advisory'] }
            ]);

            // referenceUrls should be just the URLs for FTS indexing
            expect(result.referenceUrls).toEqual([
                'https://apple.com',
                'https://mango.com',
                'https://zebra.com'
            ]);
        });

        test('should handle missing references', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.references = undefined;
            const result = normalizeCve5(mockCve);

            expect(result.references).toEqual([]);
        });

        test('should handle empty references', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.references = [];
            const result = normalizeCve5(mockCve);

            expect(result.references).toEqual([]);
        });
    });

    describe('Affected products/configurations', () => {
        test('should extract affected products', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.affected = [
                { product: 'TestProduct', vendor: 'TestVendor' },
                { product: 'AnotherProduct', vendor: 'AnotherVendor' }
            ];
            const result = normalizeCve5(mockCve);

            expect(result.configurations).toHaveLength(2);
            expect(result.configurations[0]).toEqual({
                vendor: 'TestVendor',
                product: 'TestProduct',
                defaultStatus: null,
                modules: [],
                versions: []
            });
        });

        test('should extract version information', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.affected = [
                {
                    product: 'ProductWithVersions',
                    vendor: 'TestVendor',
                    defaultStatus: 'affected',
                    modules: ['core', 'api'],
                    versions: [
                        { version: '1.0', status: 'affected', lessThan: '2.0' },
                        { version: '2.0', status: 'unaffected' }
                    ]
                }
            ];
            const result = normalizeCve5(mockCve);

            expect(result.configurations).toHaveLength(1);
            expect(result.configurations[0].defaultStatus).toBe('affected');
            expect(result.configurations[0].modules).toEqual(['core', 'api']);
            expect(result.configurations[0].versions).toHaveLength(2);
            expect(result.configurations[0].versions[0]).toEqual({
                version: '1.0',
                status: 'affected',
                lessThan: '2.0',
                lessThanOrEqual: null,
                versionType: null
            });
        });

        test('should handle missing affected products', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.affected = undefined;
            const result = normalizeCve5(mockCve);

            expect(result.configurations).toEqual([]);
        });

        test('should skip entries without product name', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.affected = [
                { vendor: 'VendorOnly' },
                { product: 'ValidProduct', vendor: 'ValidVendor' }
            ];
            const result = normalizeCve5(mockCve);

            expect(result.configurations).toHaveLength(1);
            expect(result.configurations[0].product).toBe('ValidProduct');
        });
    });

    describe('Workarounds and Solutions', () => {
        test('should extract workarounds', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.workarounds = [
                { lang: 'en', value: 'Disable the feature temporarily' },
                { lang: 'es', value: 'Desactivar la función temporalmente' }
            ];
            const result = normalizeCve5(mockCve);

            expect(result.workarounds).toHaveLength(2);
            expect(result.workarounds[0]).toEqual({
                text: 'Disable the feature temporarily',
                language: 'en'
            });
            expect(result.workarounds[1]).toEqual({
                text: 'Desactivar la función temporalmente',
                language: 'es'
            });
        });

        test('should extract solutions', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.solutions = [
                { lang: 'en', value: 'Upgrade to version 2.0 or later' }
            ];
            const result = normalizeCve5(mockCve);

            expect(result.solutions).toHaveLength(1);
            expect(result.solutions[0]).toEqual({
                text: 'Upgrade to version 2.0 or later',
                language: 'en'
            });
        });

        test('should default language to en when not specified', () => {
            const mockCve = createMockCve();
            mockCve.containers.cna.workarounds = [
                { value: 'No lang specified' }
            ];
            mockCve.containers.cna.solutions = [
                { value: 'Solution without lang' }
            ];
            const result = normalizeCve5(mockCve);

            expect(result.workarounds[0].language).toBe('en');
            expect(result.solutions[0].language).toBe('en');
        });

        test('should handle missing workarounds and solutions', () => {
            const result = normalizeCve5(createMockCve());
            expect(result.workarounds).toEqual([]);
            expect(result.solutions).toEqual([]);
        });
    });

    describe('KEV and default values', () => {
        test('should default kev to false', () => {
            const result = normalizeCve5(createMockCve());
            expect(result.kev).toBe(false);
        });
    });

    describe('Missing containers/cna', () => {
        test('should handle missing containers', () => {
            const mockCve = { cveMetadata: { cveId: 'CVE-2022-9999' } };
            const result = normalizeCve5(mockCve);

            expect(result.id).toBe('CVE-2022-9999');
            expect(result.description).toBe('No description available');
            expect(result.references).toEqual([]);
        });

        test('should handle missing cna in containers', () => {
            const mockCve = {
                cveMetadata: { cveId: 'CVE-2022-9999' },
                containers: {}
            };
            const result = normalizeCve5(mockCve);

            expect(result.id).toBe('CVE-2022-9999');
            expect(result.description).toBe('No description available');
        });
    });
});

describe('Helper Functions', () => {
    describe('computeHash', () => {
        test('should compute SHA-256 hash of data', () => {
            const hash1 = computeHash({ foo: 'bar' });
            expect(hash1).toHaveLength(64); // SHA-256 produces 64 hex chars
            expect(hash1).toMatch(/^[a-f0-9]+$/);
        });

        test('should produce same hash for same data', () => {
            const hash1 = computeHash({ foo: 'bar' });
            const hash2 = computeHash({ foo: 'bar' });
            expect(hash1).toBe(hash2);
        });

        test('should produce different hash for different data', () => {
            const hash1 = computeHash({ foo: 'bar' });
            const hash2 = computeHash({ foo: 'baz' });
            expect(hash1).not.toBe(hash2);
        });

        test('should handle nested objects', () => {
            const hash = computeHash({ a: { b: { c: 'deep' } } });
            expect(hash).toHaveLength(64);
        });

        test('should handle arrays', () => {
            const hash = computeHash({ items: [1, 2, 3] });
            expect(hash).toHaveLength(64);
        });
    });

    describe('getDiff', () => {
        test('should return empty diff for identical objects', () => {
            const obj1 = { a: 1, b: 'two' };
            const obj2 = { a: 1, b: 'two' };
            const diff = getDiff(obj1, obj2);
            expect(Object.keys(diff)).toHaveLength(0);
        });

        test('should detect changed values', () => {
            const obj1 = { a: 1, b: 'old' };
            const obj2 = { a: 1, b: 'new' };
            const diff = getDiff(obj1, obj2);

            expect(diff.b).toEqual({ from: 'old', to: 'new' });
            expect(diff.a).toBeUndefined();
        });

        test('should detect added keys', () => {
            const obj1 = { a: 1 };
            const obj2 = { a: 1, b: 2 };
            const diff = getDiff(obj1, obj2);

            expect(diff.b).toEqual({ from: undefined, to: 2 });
        });

        test('should detect removed keys', () => {
            const obj1 = { a: 1, b: 2 };
            const obj2 = { a: 1 };
            const diff = getDiff(obj1, obj2);

            expect(diff.b).toEqual({ from: 2, to: undefined });
        });

        test('should ignore hash key', () => {
            const obj1 = { a: 1, hash: 'old_hash' };
            const obj2 = { a: 1, hash: 'new_hash' };
            const diff = getDiff(obj1, obj2);

            expect(diff.hash).toBeUndefined();
        });

        test('should handle nested object changes', () => {
            const obj1 = { nested: { x: 1 } };
            const obj2 = { nested: { x: 2 } };
            const diff = getDiff(obj1, obj2);

            expect(diff.nested).toBeDefined();
        });
    });

    describe('getTimestamp', () => {
        test('should return ISO 8601 timestamp', () => {
            const timestamp = getTimestamp();
            expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
        });

        test('should return current time', () => {
            const before = new Date().toISOString();
            const timestamp = getTimestamp();
            const after = new Date().toISOString();

            expect(timestamp >= before).toBe(true);
            expect(timestamp <= after).toBe(true);
        });
    });

    describe('ensureDir', () => {
        test('should create directory if it does not exist', () => {
            const tempDir = path.join(os.tmpdir(), `nvd-test-${Date.now()}`);
            expect(fs.existsSync(tempDir)).toBe(false);

            ensureDir(tempDir);

            expect(fs.existsSync(tempDir)).toBe(true);
            // Cleanup
            fs.rmdirSync(tempDir);
        });

        test('should not throw if directory already exists', () => {
            const tempDir = path.join(os.tmpdir(), `nvd-test-${Date.now()}`);
            fs.mkdirSync(tempDir);

            expect(() => ensureDir(tempDir)).not.toThrow();

            // Cleanup
            fs.rmdirSync(tempDir);
        });

        test('should create nested directories', () => {
            const tempDir = path.join(os.tmpdir(), `nvd-test-${Date.now()}`, 'nested', 'deep');
            expect(fs.existsSync(tempDir)).toBe(false);

            ensureDir(tempDir);

            expect(fs.existsSync(tempDir)).toBe(true);
            // Cleanup
            fs.rmSync(path.join(os.tmpdir(), `nvd-test-${tempDir.split('nvd-test-')[1].split('/')[0]}`), { recursive: true });
        });
    });

    describe('walk', () => {
        test('should yield JSON files recursively', () => {
            const tempDir = path.join(os.tmpdir(), `nvd-walk-test-${Date.now()}`);
            const subDir = path.join(tempDir, 'sub');
            fs.mkdirSync(subDir, { recursive: true });

            // Create test files
            fs.writeFileSync(path.join(tempDir, 'test1.json'), '{}');
            fs.writeFileSync(path.join(subDir, 'test2.json'), '{}');
            fs.writeFileSync(path.join(tempDir, 'notjson.txt'), 'text');

            const files: string[] = [];
            for (const file of walk(tempDir)) {
                files.push(file);
            }

            expect(files).toHaveLength(2);
            expect(files.some(f => f.endsWith('test1.json'))).toBe(true);
            expect(files.some(f => f.endsWith('test2.json'))).toBe(true);

            // Cleanup
            fs.rmSync(tempDir, { recursive: true });
        });

        test('should exclude delta.json files', () => {
            const tempDir = path.join(os.tmpdir(), `nvd-walk-delta-test-${Date.now()}`);
            fs.mkdirSync(tempDir, { recursive: true });

            fs.writeFileSync(path.join(tempDir, 'test.json'), '{}');
            fs.writeFileSync(path.join(tempDir, 'delta.json'), '{}');
            fs.writeFileSync(path.join(tempDir, 'deltaLog.json'), '{}');

            const files: string[] = [];
            for (const file of walk(tempDir)) {
                files.push(file);
            }

            expect(files).toHaveLength(1);
            expect(files[0].endsWith('test.json')).toBe(true);

            // Cleanup
            fs.rmSync(tempDir, { recursive: true });
        });
    });

    describe('getChangedFiles', () => {
        // Note: These tests require the cvelistV5 repo to exist
        // If it doesn't exist, they will return null (fallback behavior)
        test('should return null when git diff fails', () => {
            // Using invalid hashes should cause git diff to fail
            const result = getChangedFiles('invalid_hash_1', 'invalid_hash_2');
            expect(result).toBeNull();
        });

        test('should return array of changed CVE files when git diff succeeds', () => {
            // Use real commit hashes from the cvelistV5 repo
            // These are known commits with CVE file changes
            const oldHash = '3267b58bb6';
            const newHash = 'a1a9e733ef';

            const result = getChangedFiles(oldHash, newHash);

            // If repo exists and hashes are valid, should return array
            if (result !== null) {
                expect(Array.isArray(result)).toBe(true);
                // Files should be .json files in cves/ directory
                for (const file of result) {
                    expect(file).toContain('/cves/');
                    expect(file.endsWith('.json')).toBe(true);
                }
            }
        });

        test('should filter to only CVE json files', () => {
            // Same test but verifying the filtering logic
            const oldHash = '4f48a76fdc';
            const newHash = '3267b58bb6';

            const result = getChangedFiles(oldHash, newHash);

            if (result !== null) {
                expect(Array.isArray(result)).toBe(true);
                // Should not include non-CVE files like README, etc
                for (const file of result) {
                    expect(file).toMatch(/cves\/.*\.json$/);
                }
            }
        });
    });
});

describe('Database Integration', () => {
    const testCveId = 'CVE-DB-INTEGRATION-TEST';

    afterEach(async () => {
        // Cleanup test data
        try {
            await db.run('DELETE FROM cve_references WHERE cve_id = ?', testCveId);
            await db.run('DELETE FROM metrics WHERE cve_id = ?', testCveId);
            await db.run('DELETE FROM configs WHERE cve_id = ?', testCveId);
            await db.run('DELETE FROM cve_changes WHERE cve_id = ?', testCveId);
            await db.run('DELETE FROM cves WHERE id = ?', testCveId);
        } catch (e) {
            // Ignore cleanup errors
        }
    });

    test('should read system_metadata', async () => {
        // Check if cvelist_commit metadata exists or can be queried
        const result = await db.get("SELECT value FROM system_metadata WHERE key = 'cvelist_commit'");
        // May or may not exist depending on previous runs
        expect(result === null || typeof result.value === 'string').toBe(true);
    });

    test('should query job_runs table', async () => {
        const jobs = await db.all('SELECT * FROM job_runs ORDER BY start_time DESC LIMIT 5');
        expect(Array.isArray(jobs)).toBe(true);
    });

    test('should support watchlist operations', async () => {
        // Insert test watchlist - SQLite returns lastID instead of RETURNING
        const insertResult = await db.run(
            'INSERT INTO watchlists (name, query_json, enabled) VALUES (?, ?, ?)',
            'Ingest Test Watchlist', '{"text":"test"}', 1
        );

        expect(insertResult.lastID).toBeGreaterThan(0);

        // Query active watchlists
        const watchlists = await db.all('SELECT * FROM watchlists WHERE enabled = 1');
        expect(Array.isArray(watchlists)).toBe(true);
        expect(watchlists.length).toBeGreaterThan(0);

        // Cleanup
        await db.run('DELETE FROM watchlists WHERE id = ?', insertResult.lastID);
    });

    test('should upsert CVE with full data', async () => {
        const testCve = {
            id: testCveId,
            description: 'Test CVE for processing',
            published: '2023-01-01T00:00:00.000Z',
            lastModified: '2023-01-02T00:00:00.000Z',
            vulnStatus: 'PUBLISHED',
            score: 7.5,
            severity: 'HIGH',
            cvssVersion: '3.1',
            references: ['https://example.com/ref1', 'https://example.com/ref2'],
            configurations: [{ product: 'TestProduct', vendor: 'TestVendor' }]
        };

        const hash = computeHash(testCve);

        // Insert CVE
        await db.run(`
            INSERT INTO cves (id, description, published, last_modified, vuln_status, normalized_hash, json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                description = excluded.description, last_modified = excluded.last_modified,
                vuln_status = excluded.vuln_status, normalized_hash = excluded.normalized_hash, json = excluded.json
        `, testCve.id, testCve.description, testCve.published, testCve.lastModified, testCve.vulnStatus, hash, JSON.stringify(testCve));

        // Verify
        const result = await db.get('SELECT * FROM cves WHERE id = ?', testCveId);
        expect(result).toBeDefined();
        expect(result.id).toBe(testCveId);
        expect(result.normalized_hash).toBe(hash);
    });

    test('should insert metrics for CVE', async () => {
        // First create the CVE
        await db.run('INSERT INTO cves (id, description, json) VALUES (?, ?, ?)', testCveId, 'Test', '{}');

        // Insert multiple metrics
        await db.run('INSERT INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES (?, ?, ?, ?, ?)',
            testCveId, '3.1', 7.5, 'HIGH', 'CVSS:3.1/...');
        await db.run('INSERT INTO metrics (cve_id, cvss_version, score, severity, vector_string) VALUES (?, ?, ?, ?, ?)',
            testCveId, '2.0', 5.0, 'MEDIUM', 'AV:N/...');

        const metrics = await db.all('SELECT * FROM metrics WHERE cve_id = ?', testCveId);
        expect(metrics).toHaveLength(2);
    });

    test('should insert references for CVE', async () => {
        await db.run('INSERT INTO cves (id, description, json) VALUES (?, ?, ?)', testCveId, 'Test', '{}');

        await db.run('INSERT INTO cve_references (cve_id, url) VALUES (?, ?)', testCveId, 'https://example.com');
        await db.run('INSERT INTO cve_references (cve_id, url) VALUES (?, ?)', testCveId, 'https://nvd.nist.gov');

        const refs = await db.all('SELECT * FROM cve_references WHERE cve_id = ?', testCveId);
        expect(refs).toHaveLength(2);
    });

    test('should insert configurations for CVE', async () => {
        await db.run('INSERT INTO cves (id, description, json) VALUES (?, ?, ?)', testCveId, 'Test', '{}');

        await db.run('INSERT INTO configs (cve_id, nodes) VALUES (?, ?)',
            testCveId,
            JSON.stringify([{ product: 'Product1', vendor: 'Vendor1' }])
        );

        const configs = await db.all('SELECT * FROM configs WHERE cve_id = ?', testCveId);
        expect(configs).toHaveLength(1);
    });

    test('should record CVE changes', async () => {
        await db.run('INSERT INTO cves (id, description, json) VALUES (?, ?, ?)', testCveId, 'Original', '{}');

        const diff = { description: { from: 'Original', to: 'Updated' } };
        await db.run('INSERT INTO cve_changes (cve_id, change_date, diff_json) VALUES (?, ?, ?)',
            testCveId,
            getTimestamp(),
            JSON.stringify(diff)
        );

        const changes = await db.all('SELECT * FROM cve_changes WHERE cve_id = ?', testCveId);
        expect(changes).toHaveLength(1);
        expect(JSON.parse(changes[0].diff_json)).toEqual(diff);
    });
});

describe('Alert Generation', () => {
    const testCveId = 'CVE-ALERT-TEST-001';
    let testWatchlistId: number;

    beforeAll(async () => {
        // Create test watchlist - SQLite uses lastID instead of RETURNING
        const result = await db.run(
            'INSERT INTO watchlists (name, query_json, enabled) VALUES (?, ?, ?)',
            'Alert Gen Test', '{"text":"alert"}', 1
        );
        testWatchlistId = result.lastID;
    });

    afterAll(async () => {
        // Cleanup
        try {
            await db.run('DELETE FROM alerts WHERE cve_id = ?', testCveId);
            await db.run('DELETE FROM watchlists WHERE id = ?', testWatchlistId);
        } catch (e) {
            // Ignore
        }
    });

    test('should check for existing alerts before creating new ones', async () => {
        // Check existing alert query works
        const existingAlert = await db.get(
            'SELECT id FROM alerts WHERE cve_id = ? AND watchlist_id = ? AND read = 0',
            testCveId, testWatchlistId
        );

        // Should be undefined for new CVE (SQLite returns undefined, not null)
        expect(existingAlert).toBeUndefined();
    });

    test('should create alert and update watchlist match count', async () => {
        // Get initial match count
        const initialWl = await db.get('SELECT match_count FROM watchlists WHERE id = ?', testWatchlistId);
        const initialCount = initialWl?.match_count || 0;

        // Insert alert
        await db.run(
            'INSERT INTO alerts (cve_id, watchlist_id, watchlist_name, type, created_at) VALUES (?, ?, ?, ?, ?)',
            testCveId, testWatchlistId, 'Alert Gen Test', 'NEW_MATCH', getTimestamp()
        );

        // Update match count (mimicking processBatch behavior)
        await db.run('UPDATE watchlists SET match_count = match_count + 1 WHERE id = ?', testWatchlistId);

        // Verify
        const updatedWl = await db.get('SELECT match_count FROM watchlists WHERE id = ?', testWatchlistId);
        expect(updatedWl.match_count).toBe(initialCount + 1);

        // Cleanup
        await db.run('DELETE FROM alerts WHERE cve_id = ?', testCveId);
    });
});
