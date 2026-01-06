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
- [ ] Add date range filtering (published/modified)
- [ ] Add filtering by vendors, products, versions, etc.
- [ ] Add filtering by vulnerability status (e.g., DISPUTED, REJECTED)

## Testing & Quality

### Test Coverage
- ✓ Write unit tests for matcher.js watchlist logic
- ✓ Add unit tests for multi-version CVSS support
- [ ] Add E2E tests for CVE search and filtering
- ✓ Test alert generation workflow
- [ ] Add tests for ingestion edge cases

## Documentation
- [ ] Document watchlist query syntax
- [ ] Add API endpoint documentation
- [ ] Create user guide for alert setup
