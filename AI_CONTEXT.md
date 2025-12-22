# Project Context: Local CVE Tracker

## 1. Project Overview
A local-only, single-user application for tracking Common Vulnerabilities and Exposures (CVEs). 
**Constraint**: "Clean-room" implementation inspired by OpenCVE but without using their code.
**Key Design Choice**: Local ingestion via Git clone of `CVEProject/cvelistV5` to avoid API rate limits and external dependencies.

## 2. Technical Architecture

### Frontend
- **Framework**: React 19 (via ESM imports in `index.html`).
- **Styling**: Tailwind CSS (CDN).
- **Icons**: Lucide React.
- **Charts**: Recharts.
- **State Management**: `useState` / `useEffect` / `fetch` in `App.tsx`.
- **Structure**: Single Page Application (SPA) mounted in `index.tsx`.

### Backend
- **Runtime**: Node.js.
- **Server**: Native `node:http` module (no Express/Fastify).
- **Database**: `better-sqlite3`.
    - **Mode**: WAL (Write-Ahead Logging).
    - **Search**: FTS5 (Full-Text Search) enabled for `description` and `refs`.
- **File System**:
    - `data/cvelistV5`: Local clone of the CVE V5 repository.
    - `cve.sqlite`: Main database file.

### Data Ingestion Strategy
1.  **Source**: `https://github.com/CVEProject/cvelistV5` (JSON 5.0 Schema).
2.  **Mechanism**:
    - **Initial**: `git clone --depth 1`.
    - **Update**: `git pull` followed by `git diff --name-only <old_hash> <new_hash>`.
3.  **Parsing**: Maps CVE JSON 5.0 format to internal `Cve` schema.
4.  **Concurrency**: Transactional batches (size: 100) to SQLite.

## 3. Current State & Recent Changes
- **Refactor**: Replaced NVD API ingestion with local `cvelistV5` Git ingestion.
- **Optimistic UI**: `App.tsx` immediately shows "Running" status upon triggering ingestion.
- **Cache Busting**: Added timestamp parameter to `/api/jobs` requests.
- **Schema**: Added `system_metadata` to track Git commit hashes (`cvelist_commit`).

## 4. Database Schema Summary
- `cves`: Core data (id, description, normalized_hash, json).
- `metrics`: CVSS scores (V2, V3.0, V3.1) and severity.
- `references`: URLs associated with CVEs.
- `configs`: Affected products/nodes.
- `job_runs`: Ingestion history.
- `watchlists`: User-defined queries (JSON).
- `alerts`: Generated matches between CVEs and Watchlists.
- `cve_changes`: Diff history for audit trails.
- `cves_fts`: Virtual table for full-text search.

## 5. Roadmap / Todo List

### Critical Missing Features
- [ ] **Alert Generation Logic**: The ingestion process (`src/lib/ingest/nvd.js`) currently saves CVEs but does **not** check against `watchlists` to generate entries in the `alerts` table. This must be implemented in the `processBatch` transaction or as a post-processing step.
- [ ] **EPSS Integration**: Schema supports `epssScore`, but no source/ingestion logic exists for it yet.

### UI Improvements
- [ ] **Pagination**: `api/cves` currently hard limits to 100 items. Server-side pagination is needed.
- [ ] **Detailed View**: Clicking a CVE should show full JSON/details (currently just a list view).

### Backend
- [ ] **Advanced Filtering**: The current "Search" in frontend is client-side. Need to expose FTS5 and SQL filtering (cvss range, date range) via API parameters.

## 6. Development Instructions
- Run server: `node src/server.js`
- Ingestion triggers via UI "Jobs" tab.
- Data location: `./data/cvelistV5` (Git repo).
