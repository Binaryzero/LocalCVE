import { matchesQuery } from '../../src/lib/matcher.js';

describe('Matcher Logic', () => {
    test('should match CVE with version-specific CVSS filtering', () => {
        const cve = {
            id: 'CVE-2022-1234',
            description: 'Test vulnerability',
            score: 7.5,
            severity: 'HIGH',
            cvssVersion: '3.1',
            cvss2Score: 5.0,
            cvss2Severity: 'MEDIUM',
            cvss30Score: 6.5,
            cvss30Severity: 'MEDIUM',
            cvss31Score: 7.5,
            cvss31Severity: 'HIGH',
            published: '2022-01-01T00:00:00.000Z',
            lastModified: '2022-01-01T00:00:00.000Z',
            kev: false,
            references: []
        };

        // Test primary CVSS filtering
        expect(matchesQuery(cve, { cvss_min: 7.0 })).toBe(true);
        expect(matchesQuery(cve, { cvss_min: 8.0 })).toBe(false);

        // Test version-specific CVSS filtering
        expect(matchesQuery(cve, { cvss2_min: 4.0 })).toBe(true);
        expect(matchesQuery(cve, { cvss2_min: 6.0 })).toBe(false);
        
        expect(matchesQuery(cve, { cvss30_min: 6.0 })).toBe(true);
        expect(matchesQuery(cve, { cvss30_min: 7.0 })).toBe(false);
        
        expect(matchesQuery(cve, { cvss31_min: 7.0 })).toBe(true);
        expect(matchesQuery(cve, { cvss31_min: 8.0 })).toBe(false);
    });

    test('should handle missing CVSS scores correctly', () => {
        const cve = {
            id: 'CVE-2022-5678',
            description: 'Test vulnerability with missing scores',
            score: null,
            severity: null,
            cvssVersion: null,
            cvss2Score: null,
            cvss2Severity: null,
            cvss30Score: null,
            cvss30Severity: null,
            cvss31Score: null,
            cvss31Severity: null,
            published: '2022-01-01T00:00:00.000Z',
            lastModified: '2022-01-01T00:00:00.000Z',
            kev: false,
            references: []
        };

        // Should handle null scores gracefully
        expect(matchesQuery(cve, { cvss_min: 0.1 })).toBe(false);
        expect(matchesQuery(cve, { cvss2_min: 0.1 })).toBe(false);
        expect(matchesQuery(cve, { cvss30_min: 0.1 })).toBe(false);
        expect(matchesQuery(cve, { cvss31_min: 0.1 })).toBe(false);
        
        // Should pass when no minimum is set
        expect(matchesQuery(cve, {})).toBe(true);
    });
});