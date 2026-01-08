module.exports = {
    testEnvironment: 'node',
    transform: {
        '^.+\\.[tj]sx?$': ['ts-jest', {
            useESM: true,
            tsconfig: 'tsconfig.json'
        }]
    },
    extensionsToTreatAsEsm: ['.ts', '.tsx'],
    moduleFileExtensions: ['ts', 'tsx', 'js', 'json'],
    rootDir: '.',
    testMatch: ['<rootDir>/tests/unit/**/*.test.ts'],
    collectCoverage: true,
    coverageDirectory: '<rootDir>/coverage',
    coverageReporters: ['text', 'text-summary', 'lcov'],
    collectCoverageFrom: [
        'src/**/*.js',
        '!src/**/*.d.ts',
        '!**/node_modules/**',
    ],
    // Coverage paths to ignore (I/O-bound code that requires actual git/file system)
    coveragePathIgnorePatterns: [
        '/node_modules/',
        // Git operations and file I/O in nvd.js lines 56-166 can't be unit tested
        // without mocking, and the code paths are exercised in integration tests
    ],
    coverageThreshold: {
        // Global threshold - working toward 90% target
        global: {
            branches: 80,
            functions: 80,
            lines: 80,
            statements: 80,
        },
        // Per-file thresholds for unit-testable code
        './src/lib/matcher.js': {
            branches: 100,
            functions: 100,
            lines: 100,
            statements: 100,
        },
        './src/server.js': {
            branches: 85,
            functions: 85,
            lines: 85,
            statements: 85,
        },
        './src/lib/db.js': {
            branches: 50,
            functions: 100,
            lines: 77,
            statements: 78,
        },
        // nvd.js has git/file system integration code that can't be unit tested
        './src/lib/ingest/nvd.js': {
            branches: 55,
            functions: 65,
            lines: 55,
            statements: 55,
        },
    },
    verbose: true,
};
