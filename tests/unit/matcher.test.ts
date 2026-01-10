import { matchesQuery, getDateRangeFromRelative } from '../../src/lib/matcher.js';

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

        test('should handle new reference format with url and tags', () => {
            const cve = createCve({
                references: [
                    { url: 'https://vendor.com/advisory', tags: ['vendor-advisory'] },
                    { url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-0001', tags: [] }
                ]
            });
            expect(matchesQuery(cve, { text: 'vendor.com' })).toBe(true);
            expect(matchesQuery(cve, { text: 'nvd.nist' })).toBe(true);
            expect(matchesQuery(cve, { text: 'nonexistent' })).toBe(false);
        });

        test('should handle mixed reference formats', () => {
            const cve = createCve({
                references: [
                    'https://old-format.com/ref',
                    { url: 'https://new-format.com/ref', tags: ['patch'] }
                ]
            });
            expect(matchesQuery(cve, { text: 'old-format' })).toBe(true);
            expect(matchesQuery(cve, { text: 'new-format' })).toBe(true);
        });

        test('should handle reference object with null url', () => {
            const cve = createCve({
                references: [
                    { url: null, tags: ['patch'] },
                    { url: 'https://valid.com', tags: [] }
                ]
            });
            expect(matchesQuery(cve, { text: 'valid.com' })).toBe(true);
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

    describe('Relative date handling', () => {
        // Helper to format date same way as the function (local time YYYY-MM-DD)
        const formatLocalDate = (d: Date) => {
            const year = d.getFullYear();
            const month = String(d.getMonth() + 1).padStart(2, '0');
            const day = String(d.getDate()).padStart(2, '0');
            return `${year}-${month}-${day}`;
        };

        test('should use relative dates when published_relative is specified', () => {
            // Create a CVE published recently (within last 7 days)
            // Use local date format to match the comparison logic
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            const recentCve = createCve({
                published: formatLocalDate(yesterday)
            });

            // Create an old CVE
            const oldCve = createCve({
                published: '2020-01-15'
            });

            // With last_7_days relative filter, recent CVE matches, old one doesn't
            expect(matchesQuery(recentCve, { published_relative: 'last_7_days' })).toBe(true);
            expect(matchesQuery(oldCve, { published_relative: 'last_7_days' })).toBe(false);
        });

        test('should use relative dates when modified_relative is specified', () => {
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            const recentlyModified = createCve({
                lastModified: formatLocalDate(yesterday)
            });

            expect(matchesQuery(recentlyModified, { modified_relative: 'last_7_days' })).toBe(true);
            expect(matchesQuery(recentlyModified, { modified_relative: 'last_30_days' })).toBe(true);
        });

        test('should prefer relative dates over absolute dates', () => {
            // Set a stale absolute date far in the past
            const oldAbsoluteDate = '2020-01-01';
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            const recentCve = createCve({
                published: formatLocalDate(yesterday)
            });

            // Even with old absolute dates, relative should take precedence
            expect(matchesQuery(recentCve, {
                published_from: oldAbsoluteDate,
                published_to: oldAbsoluteDate,
                published_relative: 'last_7_days'
            })).toBe(true);
        });
    });
});

describe('getDateRangeFromRelative', () => {
    // Helper to format date same way as the function (local time)
    const formatLocalDate = (d: Date) => {
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    };

    test('should return today for "today" preset', () => {
        const result = getDateRangeFromRelative('today');
        const today = formatLocalDate(new Date());
        expect(result.from).toBe(today);
        expect(result.to).toBeUndefined();
    });

    test('should return 7-day range for "last_7_days" preset', () => {
        const result = getDateRangeFromRelative('last_7_days');
        const today = new Date();
        const sevenDaysAgo = new Date(today);
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        expect(result.from).toBe(formatLocalDate(sevenDaysAgo));
        expect(result.to).toBe(formatLocalDate(today));
    });

    test('should return 30-day range for "last_30_days" preset', () => {
        const result = getDateRangeFromRelative('last_30_days');
        const today = new Date();
        const thirtyDaysAgo = new Date(today);
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        expect(result.from).toBe(formatLocalDate(thirtyDaysAgo));
        expect(result.to).toBe(formatLocalDate(today));
    });

    test('should return 90-day range for "last_90_days" preset', () => {
        const result = getDateRangeFromRelative('last_90_days');
        const today = new Date();
        const ninetyDaysAgo = new Date(today);
        ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);

        expect(result.from).toBe(formatLocalDate(ninetyDaysAgo));
        expect(result.to).toBe(formatLocalDate(today));
    });

    test('should return undefined for unknown preset', () => {
        const result = getDateRangeFromRelative('invalid_preset');
        expect(result.from).toBeUndefined();
        expect(result.to).toBeUndefined();
    });
});
