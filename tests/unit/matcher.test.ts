import { matchesQuery } from '../../src/lib/matcher.js';

describe('Matcher Logic', () => {
    // Base CVE object for testing
    const createCve = (overrides = {}) => ({
        id: 'CVE-2022-1234',
        description: 'Test vulnerability in example software',
        score: 7.5,
        severity: 'HIGH',
        cvssVersion: '3.1',
        cvss2Score: 5.0,
        cvss2Severity: 'MEDIUM',
        cvss30Score: 6.5,
        cvss30Severity: 'MEDIUM',
        cvss31Score: 7.5,
        cvss31Severity: 'HIGH',
        published: '2022-01-15T00:00:00.000Z',
        lastModified: '2022-02-01T00:00:00.000Z',
        kev: false,
        epssScore: 0.5,
        references: ['https://example.com/advisory', 'https://nvd.nist.gov/cve/1234'],
        ...overrides
    });

    describe('Query validation', () => {
        test('should return false for null query', () => {
            expect(matchesQuery(createCve(), null)).toBe(false);
        });

        test('should return false for undefined query', () => {
            expect(matchesQuery(createCve(), undefined)).toBe(false);
        });

        test('should return true for empty query object', () => {
            expect(matchesQuery(createCve(), {})).toBe(true);
        });
    });

    describe('Text search', () => {
        test('should match CVE ID (case insensitive)', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { text: 'CVE-2022-1234' })).toBe(true);
            expect(matchesQuery(cve, { text: 'cve-2022-1234' })).toBe(true);
            expect(matchesQuery(cve, { text: '2022-1234' })).toBe(true);
        });

        test('should match description text', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { text: 'vulnerability' })).toBe(true);
            expect(matchesQuery(cve, { text: 'EXAMPLE SOFTWARE' })).toBe(true);
        });

        test('should match reference URLs', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { text: 'nvd.nist.gov' })).toBe(true);
            expect(matchesQuery(cve, { text: 'advisory' })).toBe(true);
        });

        test('should return false when text not found', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { text: 'nonexistent' })).toBe(false);
        });

        test('should handle null id/description gracefully', () => {
            const cve = createCve({ id: null, description: null });
            expect(matchesQuery(cve, { text: 'test' })).toBe(false);
        });

        test('should handle null references array', () => {
            const cve = createCve({ references: null });
            expect(matchesQuery(cve, { text: 'advisory' })).toBe(false);
        });

        test('should handle empty references array', () => {
            const cve = createCve({ references: [] });
            expect(matchesQuery(cve, { text: 'advisory' })).toBe(false);
        });

        test('should handle references with null values', () => {
            const cve = createCve({ references: [null, 'https://example.com'] });
            expect(matchesQuery(cve, { text: 'example.com' })).toBe(true);
        });
    });

    describe('Date range filtering', () => {
        test('should filter by published_from', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { published_from: '2022-01-01T00:00:00.000Z' })).toBe(true);
            expect(matchesQuery(cve, { published_from: '2022-02-01T00:00:00.000Z' })).toBe(false);
        });

        test('should filter by published_to', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { published_to: '2022-02-01T00:00:00.000Z' })).toBe(true);
            expect(matchesQuery(cve, { published_to: '2022-01-01T00:00:00.000Z' })).toBe(false);
        });

        test('should filter by modified_from', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { modified_from: '2022-01-01T00:00:00.000Z' })).toBe(true);
            expect(matchesQuery(cve, { modified_from: '2022-03-01T00:00:00.000Z' })).toBe(false);
        });

        test('should filter by modified_to', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { modified_to: '2022-03-01T00:00:00.000Z' })).toBe(true);
            expect(matchesQuery(cve, { modified_to: '2022-01-01T00:00:00.000Z' })).toBe(false);
        });

        test('should handle date range with both bounds', () => {
            const cve = createCve();
            expect(matchesQuery(cve, {
                published_from: '2022-01-01T00:00:00.000Z',
                published_to: '2022-02-01T00:00:00.000Z'
            })).toBe(true);
        });
    });

    describe('Primary CVSS filtering', () => {
        test('should filter by cvss_min', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { cvss_min: 7.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss_min: 7.5 })).toBe(true);
            expect(matchesQuery(cve, { cvss_min: 8.0 })).toBe(false);
        });

        test('should filter by cvss_max', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { cvss_max: 8.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss_max: 7.5 })).toBe(true);
            expect(matchesQuery(cve, { cvss_max: 7.0 })).toBe(false);
        });

        test('should use 0 as default when score is null', () => {
            const cve = createCve({ score: null });
            expect(matchesQuery(cve, { cvss_min: 0.1 })).toBe(false);
            expect(matchesQuery(cve, { cvss_max: 10 })).toBe(true);
        });
    });

    describe('CVSS v2 filtering', () => {
        test('should filter by cvss2_min', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { cvss2_min: 4.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss2_min: 5.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss2_min: 6.0 })).toBe(false);
        });

        test('should filter by cvss2_max', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { cvss2_max: 6.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss2_max: 5.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss2_max: 4.0 })).toBe(false);
        });

        test('should use 0 as default when cvss2Score is null', () => {
            const cve = createCve({ cvss2Score: null });
            expect(matchesQuery(cve, { cvss2_min: 0.1 })).toBe(false);
            expect(matchesQuery(cve, { cvss2_max: 10 })).toBe(true);
        });
    });

    describe('CVSS v3.0 filtering', () => {
        test('should filter by cvss30_min', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { cvss30_min: 6.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss30_min: 6.5 })).toBe(true);
            expect(matchesQuery(cve, { cvss30_min: 7.0 })).toBe(false);
        });

        test('should filter by cvss30_max', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { cvss30_max: 7.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss30_max: 6.5 })).toBe(true);
            expect(matchesQuery(cve, { cvss30_max: 6.0 })).toBe(false);
        });

        test('should use 0 as default when cvss30Score is null', () => {
            const cve = createCve({ cvss30Score: null });
            expect(matchesQuery(cve, { cvss30_min: 0.1 })).toBe(false);
            expect(matchesQuery(cve, { cvss30_max: 10 })).toBe(true);
        });
    });

    describe('CVSS v3.1 filtering', () => {
        test('should filter by cvss31_min', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { cvss31_min: 7.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss31_min: 7.5 })).toBe(true);
            expect(matchesQuery(cve, { cvss31_min: 8.0 })).toBe(false);
        });

        test('should filter by cvss31_max', () => {
            const cve = createCve();
            expect(matchesQuery(cve, { cvss31_max: 8.0 })).toBe(true);
            expect(matchesQuery(cve, { cvss31_max: 7.5 })).toBe(true);
            expect(matchesQuery(cve, { cvss31_max: 7.0 })).toBe(false);
        });

        test('should use 0 as default when cvss31Score is null', () => {
            const cve = createCve({ cvss31Score: null });
            expect(matchesQuery(cve, { cvss31_min: 0.1 })).toBe(false);
            expect(matchesQuery(cve, { cvss31_max: 10 })).toBe(true);
        });
    });

    describe('KEV filtering', () => {
        test('should filter KEV-only when kev=true in query', () => {
            const kevCve = createCve({ kev: true });
            const nonKevCve = createCve({ kev: false });

            expect(matchesQuery(kevCve, { kev: true })).toBe(true);
            expect(matchesQuery(nonKevCve, { kev: true })).toBe(false);
        });

        test('should ignore KEV filter when not specified', () => {
            const kevCve = createCve({ kev: true });
            const nonKevCve = createCve({ kev: false });

            expect(matchesQuery(kevCve, {})).toBe(true);
            expect(matchesQuery(nonKevCve, {})).toBe(true);
        });

        test('should not filter when kev=false in query', () => {
            const nonKevCve = createCve({ kev: false });
            expect(matchesQuery(nonKevCve, { kev: false })).toBe(true);
        });
    });

    describe('EPSS filtering', () => {
        test('should filter by epss_min', () => {
            const cve = createCve({ epssScore: 0.5 });
            expect(matchesQuery(cve, { epss_min: 0.3 })).toBe(true);
            expect(matchesQuery(cve, { epss_min: 0.5 })).toBe(true);
            expect(matchesQuery(cve, { epss_min: 0.7 })).toBe(false);
        });

        test('should use 0 as default when epssScore is null', () => {
            const cve = createCve({ epssScore: null });
            expect(matchesQuery(cve, { epss_min: 0.1 })).toBe(false);
        });

        test('should use 0 as default when epssScore is undefined', () => {
            const cve = createCve();
            delete cve.epssScore;
            expect(matchesQuery(cve, { epss_min: 0.1 })).toBe(false);
        });
    });

    describe('Combined filters', () => {
        test('should match with multiple filters', () => {
            const cve = createCve();
            expect(matchesQuery(cve, {
                text: 'vulnerability',
                cvss_min: 7.0,
                published_from: '2022-01-01T00:00:00.000Z'
            })).toBe(true);
        });

        test('should fail if any filter fails', () => {
            const cve = createCve();
            expect(matchesQuery(cve, {
                text: 'vulnerability',
                cvss_min: 9.0  // This will fail
            })).toBe(false);
        });

        test('should handle complex query with all version-specific CVSS filters', () => {
            const cve = createCve();
            expect(matchesQuery(cve, {
                cvss_min: 7.0,
                cvss2_min: 4.0,
                cvss30_min: 6.0,
                cvss31_min: 7.0
            })).toBe(true);
        });
    });
});
