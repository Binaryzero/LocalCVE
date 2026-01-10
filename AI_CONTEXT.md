# Project Context: CVE Tracker

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
- **Virtual Scrolling**: @tanstack/react-virtual for 326k+ CVE list.
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
1. **Primary Source**: `https://github.com/CVEProject/cvelistV5` (JSON 5.0 Schema).
2. **Enrichment Sources**:
   - CVSS-BT (EPSS, exploit maturity, threat intel sources)
   - Trickest (GitHub PoC links, security advisories)
   - CISA KEV catalog (known exploited vulnerabilities)
3. **Mechanism**:
    - **Initial**: `git clone --depth 1` or bulk mode for fast import.
    - **Update**: `git pull` followed by `git diff --name-only <old_hash> <new_hash>`.
4. **Parsing**: Maps CVE JSON 5.0 format to internal schema with CNA and ADP metrics extraction.
5. **Concurrency**: Transactional batches (size: 5000) with FTS5 rebuild and alert generation.

## 3. Current State (Jan 2026)
- **CVE Count**: 326,845 CVEs fully ingested
- **Database**: 100% complete with all enrichment data
- **CVSS Support**: 2.0, 3.0, 3.1, and 4.0 versions
- **Threat Intel**: EPSS scores, exploit maturity, 6 threat intel sources

## 4. Database Schema Summary
- `cves`: Core data (id, description, title, published, last_modified, json).
- `metrics`: CVSS scores (V2, V3.0, V3.1, V4.0) and severity.
- `cve_references`: URLs with tags associated with CVEs.
- `configs`: Affected products/vendors with version information.
- `job_runs`: Ingestion history with progress tracking.
- `job_logs`: Persistent logging for ingestion jobs.
- `watchlists`: User-defined queries (JSON).
- `alerts`: Generated matches between CVEs and Watchlists.
- `cve_changes`: Diff history for audit trails.
- `cve_temporal`: CVSS-BT enrichment (EPSS, exploit maturity).
- `cve_exploits`: Trickest PoC links and security advisories.
- `cve_cwes`: CWE classifications.
- `cve_capec`: CAPEC attack patterns.
- `cve_ssvc`: CISA SSVC prioritization scores.
- `cve_workarounds`: Mitigation guidance.
- `cve_solutions`: Official remediation info.
- `cves_fts`: Virtual table for full-text search.
- `system_metadata`: Key-value store for Git commit hashes.

## 5. Key Features Implemented
- Full-text search with FTS5
- Multi-version CVSS filtering (2.0, 3.0, 3.1, 4.0)
- Server-side pagination and sorting
- Watchlist alert generation with deduplication
- CVSS-BT integration (EPSS, exploit maturity)
- Trickest PoC links integration
- Split pane layout with keyboard navigation
- Filter presets with custom query editor
- Settings page with preference management
- Real-time job logging via SSE

## 6. Development Instructions
- Run production server: `npm start`
- Run development (two servers): `npm run dev:backend` + `npm run dev`
- Run tests: `npm test` (unit), `npm run e2e` (Playwright)
- Data location: `./data/cvelistV5` (Git repo), `./cve.sqlite` (database)

## 7. Security Guidelines
Security best practices are documented in `.github/instructions/`:
- Input validation and injection defense (parameterized queries throughout)
- API security (rate limiting, CORS, validation)
- Logging with redaction of sensitive data
