# LocalCVE - Project Status

## Project Overview
**CVE Tracker** (formerly LocalCVE) is a local-first CVE (Common Vulnerabilities and Exposures) tracking application built with:
- React 19 + Vite
- TypeScript
- SQLite database (better-sqlite3) with FTS5 full-text search
- Recharts for data visualization
- Playwright for E2E testing
- Jest for unit testing

## Repository
- **Remote**: https://github.com/Binaryzero/LocalCVE.git
- **Branch**: main
- **Latest PR**: #4 (DuckDB Migration - now reverted to SQLite)

## Current State (Jan 9, 2026)

### Database
- **Engine**: SQLite with better-sqlite3 (reverted from DuckDB)
- **CVE Count**: 326,845
- **Completeness**: 100%
- **Status**: Healthy

### Recent Session Summary
CVE Navigation Improvements:
1. **Collapsible REFERENCES** - Matches other collapsible sections in detail view
2. **Prev/Next navigation** - Navigate between CVEs without returning to list, with keyboard shortcuts (Arrow keys, J/K, Escape)
3. **Sticky list position** - Scroll position saved/restored when navigating, last-viewed CVE highlighted with cyan animation
4. **Split pane layout** - Toggle button for side-by-side list + detail view, persisted to localStorage

Previous session (Jan 9):
1. **CVSS-BT enrichment** - EPSS scores, exploit maturity, threat intel source indicators
2. **Trickest integration** - GitHub exploit PoC links and security advisories
3. **Exploit badges** - Clickable badges with counts, scrollable exploit lists

Earlier (Jan 8):
UI polish and usability fixes:
1. **Badge deduplication** - Alerts badge now shows only once (on icon when collapsed, at label when expanded)
2. **Pulse animation removed** - No more pulsing dot on active menu items
3. **Editable presets** - Filter presets can now be removed (including default ones)
4. **Relative date presets** - Changed from "7D" to "Today", "Last 7 Days", "Last 30 Days"
5. **Compact date filters** - Published and modified dates now side-by-side on same row
6. **Modified filter fixed** - Was working but required server restart

Previous sessions (same day):
- **UI/UX improvements** - Full-width grid, alert badge, recently updated filter
- **Data grid improvements** - Pagination, flexbox layout, server-side sorting
- **CVE detail cleanup** - Removed versionType/defaultStatus from affected products
- **CVSS 4.0 support** - Full CVSS 4.0 extraction, filtering, and display (16,473 CVEs updated)
- **Job stats fix** - Final completion UPDATE now writes items_added/updated/unchanged
- **CVSS scores showing N/A** - Added ADP metrics extraction (31,904 CVEs updated)

### Key Features Working
- Full-text search on CVE IDs and descriptions
- CVSS filtering (min score, version-specific)
- KEV (Known Exploited Vulnerabilities) filtering
- Date range filtering
- Vendor/product filtering
- Alert generation from watchlists
- Real-time ingestion with progress tracking
- Bulk import mode for fast initial load

## Technology Stack

### Frontend
- React 19
- lucide-react (icons)
- recharts (charting)
- @tanstack/react-virtual (virtual scrolling)

### Backend
- Node.js native HTTP server (no Express/Fastify)
- better-sqlite3 with FTS5
- SSE for real-time log streaming

### Development Tools
- Vite (build tool)
- TypeScript
- Jest (unit testing)
- Playwright (E2E testing)

## Running the Application

**IMPORTANT**: Always use `npm start` (sets NODE_ENV=production)

```bash
# Start production server (serves both API and static files)
npm start

# Access at http://127.0.0.1:17920
```

## Known Limitations
- DuckDB migration abandoned due to Node.js binding instability
- EPSS integration not yet implemented
- Some server.test.ts tests disabled due to ESM/Jest compatibility

## Recent Changes

### 2026-01-08: UI Polish (Latest)
- Badge fix: Alerts badge only shows once (on icon when collapsed, at label when expanded)
- Removed pulse animation from active menu indicator
- Filter presets: Now fully editable/removable (no locked built-in presets)
- Date presets: Changed to relative labels ("Today", "Last 7 Days", "Last 30 Days")
- Date filters: Combined published and modified onto same row (side-by-side)
- Build verified (670KB), all 109 tests passing

### 2026-01-08: UI/UX Improvements
- Full-width grid: Removed max-w-7xl constraint from Layout.tsx
- Watchlist edit: Added modified date range, vendors, products fields
- Alert indicator: Added unread count badge to navigation with 99+ overflow handling
- Recently updated filter: Added modified_from/modified_to API parameters
- CVE detail cleanup: Removed versionType/defaultStatus from affected products
- Build verified (671KB), all 109 tests passing

### 2026-01-08: Data Grid Improvements
- Fixed pagination visibility (shows only when results exist and search is active)
- Restructured grid container with flexbox for responsive height
- Pagination now inside flex container (no scrolling up needed)
- Added server-side column sorting:
  - Sortable columns: CVE ID, Severity, Published
  - Click header to sort, click again to toggle direction
  - Up/down chevron indicates sort direction
  - Server-side sorting ensures consistency across pages
- Build verified (667KB), all 109 tests passing

### 2026-01-08: UI Improvements & Test Fixes
- Verified all UI improvements from previous session are complete:
  - Date input calendar visibility (cyan-tinted icons on dark background)
  - Collapsible sidebar with localStorage persistence
  - CVE list flex height (`calc(100vh - 420px)`)
  - Improved pagination with page numbers and first/last buttons
- Fixed test parameter syntax for SQLite compatibility:
  - Changed `$1, $2, $3` (DuckDB style) to `?` (SQLite style)
  - Fixed `RETURNING id` to use `lastID` from run result
  - Updated version priority test expectation (v3.1 > v3.0)
- All 109 unit tests passing

### 2026-01-08: CVSS 4.0 Support & Job Stats Fix
- Added full CVSS 4.0 extraction from CNA and ADP containers
- Added CVSS 4.0 filtering via cvss40_min API parameter
- Added CVSS 4.0 display in CvssVersionTabs with vector breakdown
- Added CVSS 4.0 column to SeverityMatrix filter
- Fixed job completion stats not persisting (items_added/updated/unchanged showed 0)
- Fixed stale log message "DuckDB FTS extension" → "FTS5 index rebuilt"
- Full re-ingestion updated 16,473 CVEs with CVSS 4.0 metrics

### 2026-01-08: DuckDB to SQLite Reversion
- Reverted from DuckDB to SQLite due to segfault crashes
- Added ADP metrics extraction for CVSS scores
- Fixed search parameter binding bug
- Fixed KEV filter comparison
- Full re-ingestion completed with 31,904 CVE updates

### 2026-01-08: DuckDB Migration (later reverted)
- Attempted migration to DuckDB for analytical performance
- Encountered stability issues with large datasets
- Decision made to revert to battle-tested SQLite

### 2026-01-07: CVE Detail Enhancements
- Added CWE, CAPEC, SSVC data extraction
- Added workarounds and solutions sections
- Made affected products clickable for filtering
- Expanded version information display

## Files Modified This Session
- `App.tsx` - Layout mode state, toggle handler, split pane grid layout
- `components/CveList.tsx` - Layout toggle button, scroll position restoration, highlight animation, compact split mode columns
- `components/CveDetail.tsx` - showBackButton prop for split mode, collapsible REFERENCES
- `index.html` - highlight-fade keyframe animation
- `TODO.md` - Session updates
- `project_status.md` - Session updates

## Recent Changes

### 2026-01-09: CVE Navigation Improvements (Latest)
- Made REFERENCES section collapsible (matches other sections)
- Added Prev/Next CVE navigation with keyboard shortcuts (Arrow keys, J/K, Escape)
- Added sticky list position with scroll restoration and highlight animation
- Added split pane layout with toggle button and localStorage persistence
- Build verified (372KB), 139 tests passing

### 2026-01-09: CVSS-BT & Trickest Integration
- Added CVSS-BT enrichment (EPSS scores, exploit maturity, threat intel sources)
- Added Trickest PoC links integration
- Clickable exploit badges with counts
- Scrollable exploit lists with gradient indicators

## Next Steps
1. Document watchlist query syntax
2. Create user guide for alert setup
