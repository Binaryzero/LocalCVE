import { normalizeCve5 } from '../../src/lib/ingest/nvd.js';

describe('CVE Normalization', () => {
    test('should collect all CVSS versions', () => {
        const mockCve = {
            cveMetadata: {
                cveId: 'CVE-2022-1234',
                state: 'PUBLISHED',
                datePublished: '2022-01-01T00:00:00.000Z',
                dateUpdated: '2022-01-01T00:00:00.000Z'
            },
            containers: {
                cna: {
                    descriptions: [{ lang: 'en', value: 'Test vulnerability' }],
                    metrics: [
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
                    ],
                    references: [{ url: 'https://example.com' }]
                }
            }
        };

        const normalized = normalizeCve5(mockCve);
        
        // Check that all versions are collected
        expect(normalized.allMetrics).toHaveLength(3);
        
        // Check version-specific fields
        expect(normalized.cvss2Score).toBe(5.0);
        expect(normalized.cvss2Severity).toBe('MEDIUM');
        expect(normalized.cvss30Score).toBe(6.5);
        expect(normalized.cvss30Severity).toBe('MEDIUM');
        expect(normalized.cvss31Score).toBe(7.5);
        expect(normalized.cvss31Severity).toBe('HIGH');
        
        // Check that primary score is the highest priority (3.1)
        expect(normalized.cvssVersion).toBe('3.1');
        expect(normalized.score).toBe(7.5);
        expect(normalized.severity).toBe('HIGH');
    });

    test('should handle CVE with only one CVSS version', () => {
        const mockCve = {
            cveMetadata: {
                cveId: 'CVE-2022-5678',
                state: 'PUBLISHED',
                datePublished: '2022-01-01T00:00:00.000Z',
                dateUpdated: '2022-01-01T00:00:00.000Z'
            },
            containers: {
                cna: {
                    descriptions: [{ lang: 'en', value: 'Test vulnerability' }],
                    metrics: [
                        {
                            cvssV2_0: {
                                baseScore: 5.0,
                                baseSeverity: 'MEDIUM',
                                vectorString: 'AV:N/AC:L/Au:N/C:N/I:P/A:N'
                            }
                        }
                    ],
                    references: [{ url: 'https://example.com' }]
                }
            }
        };

        const normalized = normalizeCve5(mockCve);
        
        // Check that only one version is collected
        expect(normalized.allMetrics).toHaveLength(1);
        
        // Check version-specific fields
        expect(normalized.cvss2Score).toBe(5.0);
        expect(normalized.cvss2Severity).toBe('MEDIUM');
        expect(normalized.cvss30Score).toBeNull();
        expect(normalized.cvss31Score).toBeNull();
        
        // Check that primary score is set correctly
        expect(normalized.cvssVersion).toBe('2.0');
        expect(normalized.score).toBe(5.0);
        expect(normalized.severity).toBe('MEDIUM');
    });
});