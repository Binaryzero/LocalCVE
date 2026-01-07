# LocalCVE - TODO List

## Current Status
LocalCVE has basic CVE ingestion and viewing capabilities. Core infrastructure is complete. Git repository initialized, merged with remote, and PR #1 created for review.

## Completed Tasks
- ✓ Git-based CVE ingestion from cvelistV5 repository
- ✓ SQLite database with FTS5 full-text search
- ✓ React UI with CVE list view
- ✓ Backend API server with search and filtering
- ✓ Watchlist and alert database schema
- ✓ Created comprehensive CLAUDE.md file with architecture and development guide
- ✓ Initialized git repository (commit 43aa7e4)
- ✓ Updated .gitignore to exclude database files and CVE data
- ✓ Connected to GitHub remote (origin)
- ✓ Merged remote history with local code (commit da2ea2c)
- ✓ Created PR #1: Sync local updates to GitHub
- ✓ **Migrated to single-server architecture** for production (Jan 5, 2026)
- ✓ Server now serves both API and static files in production mode
- ✓ Maintained two-server dev mode for HMR functionality
- ✓ Updated package.json scripts (npm start for production)
- ✓ Created PRODUCTION.md usage guide
- ✓ Updated CLAUDE.md with new architecture details
- ✓ **All tests verified** (Jan 5, 2026)
- ✓ Fixed E2E tests to match actual UI elements
- ✓ Removed scanline effect from frontend
- ✓ Production build verified working (1.18s build time)
- ✓ **Fixed critical ingestion bugs** (Jan 5, 2026)
- ✓ Fixed "no changes" false positive by checking stored hash after git pull
- ✓ Fixed matcher.js null reference crash (defensive null checks)
- ✓ Ingestion now forces full scan when no stored hash exists
- ✓ Full scan triggered and running (136k+ CVEs processed, ongoing)
- ✓ Unit tests verified passing after fixes (1/1)
- ✓ **Fixed production mode serving** (Jan 5, 2026)
- ✓ Server now properly runs with NODE_ENV=production via npm start
- ✓ Serves built assets from dist/ instead of source files
- ✓ Application loads correctly in browser (no MIME type errors)
- ✓ **UI cleanup** (Jan 5, 2026)
- ✓ Removed fake status indicators (ONLINE, MONITORING, LIVE, OK)
- ✓ Removed Dashboard component with inaccurate statistics
- ✓ Removed "Local Mode" and "LocalCVE" branding references
- ✓ Changed app name to "CVE Tracker" throughout UI
- ✓ Threats page now the default landing page
- ✓ Bundle size reduced from 587KB to 241KB (60% reduction)
- ✓ All tests updated and passing (1/1 unit, 3/3 E2E)
- ✓ **Search-focused UI improvements** (Jan 5, 2026)
- ✓ Refactored Threats/CVE screen to search-first design (no default data display)
- ✓ Improved CVSS filter with dual input: slider (whole numbers) + text input (0.1 precision)
- ✓ Removed 100 alert limit from Alerts page
- ✓ Added KEV filtering support to alerts API
- ✓ Added "Mark all read" bulk action to Alerts page
- ✓ Added "Delete all" bulk action to Alerts page with confirmation
- ✓ All tests updated and passing (1/1 unit, 3/3 E2E)
- ✓ **Multi-Version CVSS Support & Enhanced Alert Generation** (Jan 6, 2026)
- ✓ Implemented multi-version CVSS collection (2.0, 3.0, 3.1)
- ✓ Enhanced alert generation with deduplication and error handling
- ✓ Added version-specific CVSS filtering to API and matcher
- ✓ Updated TypeScript types for all CVSS versions
- ✓ Created comprehensive unit tests for new functionality
- ✓ Created PR #2 with all changes
- ✓ All tests verified passing (5/5 unit, 3/3 E2E)
- ✓ **Security Compliance Review & Input Validation** (Jan 6, 2026)
- ✓ Conducted full audit against all 22 codeguard security rules
- ✓ Verified SQL injection protection (prepared statements throughout)
- ✓ Verified no hardcoded credentials in codebase
- ✓ Verified XSS protection (React auto-escaping, rel="noopener noreferrer")
- ✓ Verified cryptographic usage (SHA-256 correctly implemented)
- ✓ Implemented comprehensive input validation in server.js:
  - ✓ Request body size limit (1MB max)
  - ✓ Search parameter length limit (500 chars)
  - ✓ Limit parameter bounding (1-1000, default 100)
  - ✓ Offset validation (non-negative)
  - ✓ Severity enum validation (LOW/MEDIUM/HIGH/CRITICAL)
  - ✓ CVSS range validation (0-10)
  - ✓ Watchlist body structure validation (name, query required)
- ✓ All tests passing (5/5 unit)
- ✓ **Documentation Update** (Jan 6, 2026)
- ✓ Updated README.md with comprehensive project documentation
- ✓ Includes features, quick start, architecture, API reference, troubleshooting
- ✓ **UI Visual Refresh** (Jan 6, 2026)
- ✓ Changed background from dark teal (#0a0e1a) to pure black (#000000)
- ✓ Updated surface colors to neutral grays for cleaner look
- ✓ Softened cyan accent color for less visual noise
- ✓ Added accessibility focus states (visible outline on focus)
- ✓ Added prefers-reduced-motion support for accessibility
- ✓ Made grid pattern more subtle (nearly invisible)
- ✓ Slimmed scrollbar design for minimal appearance
- ✓ All E2E tests passing (3/3)
- ✓ **Ingestion System Overhaul** (Jan 6, 2026)
- ✓ Complete revamp of job management system:
  - ✓ Added job cancellation mechanism with cooperative cancellation checkpoints
  - ✓ Added persistent job logging (job_logs table with DB storage)
  - ✓ Added real-time log streaming via Server-Sent Events (SSE)
  - ✓ Added git operation timeouts (10min clone, 5min pull) with retry logic
  - ✓ Added stuck job auto-detection (marks jobs FAILED if no heartbeat for 10+ min)
  - ✓ Added detailed progress tracking (added/updated/unchanged counts)
  - ✓ Added progress percentage with responsive UI updates every 100 files
  - ✓ Migrated from execSync to spawnSync for safer git operations
- ✓ New database columns: progress_percent, items_added, items_updated, items_unchanged, current_phase, cancel_requested, last_heartbeat, total_files
- ✓ New API endpoints:
  - ✓ POST /api/jobs/:id/cancel - Request job cancellation
  - ✓ GET /api/jobs/:id/logs - Retrieve job logs
  - ✓ GET /api/jobs/:id/logs/stream - SSE streaming for real-time logs
- ✓ Enhanced Jobs.tsx UI:
  - ✓ Cancel button for running jobs
  - ✓ Progress bar with percentage
  - ✓ Change counts display (+added, ~updated, =unchanged)
  - ✓ Expandable log panel with real-time streaming
  - ✓ CANCELLED status badge support
- ✓ Build verified, unit tests passing (210/213)
- ✓ **Phase 1 UI Enhancements** (Jan 6, 2026)
- ✓ Multi-Version CVSS Display:
  - ✓ Created CvssVersionTabs component with tabbed interface
  - ✓ Visual comparison chart using Recharts
  - ✓ CVSS vector string breakdown with tooltips
  - ✓ Severity-based color coding
- ✓ Date Range Filtering:
  - ✓ Added published_from/published_to API parameters
  - ✓ Native date input fields in filter panel
  - ✓ Quick presets (7D, 30D, 90D, YTD)
  - ✓ Clear dates button
- ✓ Filter Presets:
  - ✓ Created FilterPresets component
  - ✓ Built-in presets: Critical Only, High + Recent, Known Exploited
  - ✓ Custom preset saving to localStorage
  - ✓ Preset activation detection
- ✓ Virtual Scrolling:
  - ✓ Implemented @tanstack/react-virtual
  - ✓ Grid-based layout replacing table
  - ✓ 600px max height with virtualized rows
  - ✓ 72px estimated row height with 5 item overscan
- ✓ 218 unit tests passing, build verified

## Critical Missing Features

### Alert Generation Logic
- ✓ Implement watchlist matching in ingestion process
- ✓ Generate alerts table entries when CVEs match watchlist queries
- ✓ Add alert matching to `processBatch` transaction in src/lib/ingest/nvd.js
- ✓ Test alert generation with sample watchlists
- ✓ Enhance alert generation with deduplication and error handling
- ✓ Add watchlist match count tracking

### EPSS Integration
- [ ] Research EPSS data source (FIRST.org API or CSV)
- [ ] Add EPSS score ingestion logic
- [ ] Populate epssScore field in CVE records
- [ ] Display EPSS scores in UI

## UI Improvements

### Pagination (COMPLETED)
- ✓ Server-side pagination implemented for /api/cves endpoint
- ✓ Page navigation controls added to CveList component
- ✓ Total count and page state handled in frontend

### CVE Detail View (COMPLETED)
- ✓ Detailed CVE component created
- ✓ Shows full JSON data and all metadata
- ✓ Displays references, configurations, and change history
- ✓ Click handler added to CVE list items

## Backend Enhancements

### Advanced Filtering
- ✓ Expose FTS5 search via API query parameters
- ✓ Add CVSS score range filtering (min/max)
- ✓ Update frontend to use server-side search/filtering
- ✓ Add KEV filtering support to alerts
- ✓ Add multi-version CVSS filtering support (cvss2_min, cvss30_min, cvss31_min)
- ✓ Add date range filtering (published_from, published_to)
- [ ] Add filtering by vendors, products, versions, etc.
- [ ] Add filtering by vulnerability status (e.g., DISPUTED, REJECTED)

## Testing & Quality

### Test Coverage
- ✓ Write unit tests for matcher.js watchlist logic
- ✓ Add unit tests for multi-version CVSS support
- [ ] Add E2E tests for CVE search and filtering
- ✓ Test alert generation workflow
- ✓ Add tests for ingestion edge cases
- ✓ **Comprehensive Unit Test Suite** (Jan 6, 2026)
  - ✓ 213 total tests across 4 test files
  - ✓ 85.97% statement coverage (527/613)
  - ✓ 87.76% branch coverage (251/286)
  - ✓ matcher.js: 100% coverage
  - ✓ server.js: 95.05% coverage
  - ✓ db.js: 78.26% coverage (schema migration code excluded)
  - ✓ nvd.js: 73.12% coverage (git/file operations excluded)
  - ✓ All configured per-file thresholds passing
  - ✓ Added server.test.ts with comprehensive API endpoint tests
  - ✓ Added processBatch tests for CVE ingestion
  - ✓ Added CVSS version-specific tests (2.0, 3.0, 3.1)
  - ✓ Added alert generation and deduplication tests
  - ✓ Added FTS5 search operation tests

## Documentation
- [ ] Document watchlist query syntax
- ✓ Add API endpoint documentation (in README.md)
- [ ] Create user guide for alert setup
