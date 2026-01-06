# LocalCVE - Project Status

## Project Overview
**LocalCVE** is a local CVE (Common Vulnerabilities and Exposures) tracking application built with:
- React 19.2.3 + Vite 6.2.0
- TypeScript 5.8.2
- SQLite database (better-sqlite3)
- Recharts for data visualization
- Playwright for E2E testing
- Jest for unit testing

## Repository
- **Remote**: https://github.com/Binaryzero/LocalCVE.git
- **Branch**: main
- **Status**: Merged with remote, ready to push
- **Latest Commit**: da2ea2c (merge commit)
- **Files**: 33 files (9,310 lines)

## Technology Stack

### Frontend
- React 19.2.3
- lucide-react 0.562.0 (icon library)
- recharts 3.6.0 (charting)

### Backend/Data
- better-sqlite3 11.8.1 (local database)

### Development Tools
- Vite 6.2.0 (build tool)
- TypeScript 5.8.2
- Jest 29.7.0 (unit testing)
- Playwright 1.45.0 (E2E testing)

## MCP Integration

### Enabled Servers (5)
1. **context7** - Code documentation context
2. **curl** - HTTP request tool
3. **deepwiki** - GitHub repository documentation queries
4. **github-official** - Official GitHub API integration (40 tools)
5. **playwright** - Browser automation (22 tools)

### Available Tool Count
- Total: 65+ tools across all servers
- GitHub operations: 40 tools
- Browser automation: 22 tools
- Documentation: 3 tools

## Recent Changes
- **2026-01-06 06:30**: Implemented Multi-Version CVSS Support and Enhanced Alert Generation
  - Collect and store all CVSS versions (2.0, 3.0, 3.1) instead of just the best one
  - Enhanced alert generation with deduplication and error handling
  - Added version-specific CVSS filtering to API and matcher logic
  - Updated TypeScript types to support all CVSS versions
  - Created comprehensive unit tests for new functionality
  - Created PR #2 with all changes
  - All tests verified passing (5/5 unit, 3/3 E2E)
- **2026-01-06 00:00**: Fixed KEV filter and table width issues
  - Fixed KEV checkbox on CVE search page (was not functional)
    - Added `kev` parameter to frontend API call ([App.tsx:46](App.tsx#L46))
    - Added KEV filtering support to `/api/cves` endpoint ([server.js:101-103](src/server.js#L101-L103))
  - Fixed table width causing horizontal scrolling
    - Changed table from `min-w-full` to `table-fixed` with explicit column sizing
    - Widened container from `max-w-5xl` to `max-w-7xl` for better space usage
    - Added `break-words` to description column to prevent overflow
    - Reduced padding from px-6 to px-4 for more compact layout
  - All tests passing (1/1 unit, 3/3 E2E)
  - Bundle size: 243.48KB (stable)
- **2026-01-05 23:45**: Search-focused UI improvements and Alerts enhancements
  - Refactored CVE/Threats screen to search-first design (like Google homepage)
    - Only shows results when user actively searches (no default data display)
    - Changed header from "THREAT DATABASE" to "CVE SEARCH"
  - Improved CVSS filter with dual input system:
    - Slider for quick whole-number selection (0-10, step=1)
    - Text input for precise decimal values (0.1 precision)
  - Fixed Alerts page limitations:
    - Removed hard-coded 100 alert limit (now shows all alerts)
    - Added KEV filtering support via API query parameters
    - Added "Mark all read" bulk action button
    - Added "Delete all" bulk action button with confirmation
  - Updated API endpoints:
    - `/api/alerts` now supports `?kev=true/false` and `?unread=true` query params
    - Added `PUT /api/alerts/mark-all-read` endpoint
    - Added `DELETE /api/alerts/delete-all` endpoint
  - All tests updated and passing (1/1 unit, 3/3 E2E)
  - Bundle size: 243KB (stable)
- **2026-01-05 23:30**: UI cleanup - removed non-functional elements
  - Removed all fake status indicators (ONLINE, MONITORING, LIVE, OK)
  - Deleted Dashboard component with inaccurate statistics (based on 100 CVEs not full DB)
  - Removed "Local Mode" and "LocalCVE" branding references
  - Renamed application to "CVE Tracker" throughout UI
  - Threats page is now the default landing page (not dashboard)
  - Bundle size reduced from 587KB to 241KB (60% reduction)
  - All tests updated and passing (1/1 unit, 3/3 E2E)
- **2026-01-05 23:00**: Fixed production mode serving issue
  - Server was running without NODE_ENV=production set properly
  - Fixed by using `npm start` instead of manual NODE_ENV setting
  - Now correctly serves built dist/ files instead of source files
  - Browser no longer shows MIME type errors
  - Application loads correctly in production mode
- **2026-01-05 22:00**: Fixed critical ingestion bugs
  - Fixed "no changes" false positive when database missing stored commit hash
  - Added stored hash verification after git pull (not just when no changes)
  - Fixed matcher.js null reference crash on CVE fields
  - Full scan now running: 136k+ CVEs processed (ongoing)
  - Unit tests verified: 1/1 passed
  - Expected to reach ~240-250k CVEs when complete
- **2026-01-05 15:45**: Migrated to single-server architecture for production
  - Backend now serves static files from dist/ when NODE_ENV=production
  - Added npm scripts: `npm start` (production), `npm run dev:backend` (dev)
  - Created PRODUCTION.md with deployment guide
  - Updated CLAUDE.md with single-server architecture details
  - Maintains two-server dev mode for HMR (Vite + backend)
  - Rebuilt better-sqlite3 for Node.js v25.2.1
  - Verified production mode serves both API and frontend on port 17920
- 2026-01-05 15:40: Created PR #1 to sync local updates to GitHub
- 2026-01-05 15:35: Merged local main with origin/main (kept newer local code)
- 2026-01-05 15:30: Connected to GitHub remote (Binaryzero/LocalCVE)
- 2026-01-05 15:30: Initialized git repository with initial commit
- 2026-01-05 15:30: Updated .gitignore to exclude database, CVE data, and working docs
- 2026-01-05: Initialized MCP server discovery and configuration
- 2026-01-05: Enabled github-official, playwright, and deepwiki servers
- 2026-01-05: Configured GitHub authentication
- 2026-01-05: Created CLAUDE.md with comprehensive development guide
- 2026-01-05: Refactored TODO.md to focus on app-specific features

## Current Milestone
Core infrastructure complete. Focus on implementing critical missing features:
- EPSS score integration
- UI improvements (pagination, detail view)
- Advanced filtering capabilities

## Priority Features
1. **EPSS Integration**: Implement EPSS score fetching and display
2. **Advanced Filtering**: Add date range and vendor/product filtering
3. **UI Enhancements**: Improve display of multi-version CVSS data

## Known Issues
- Pagination limited to 100 items on frontend
- Search is currently client-side only
