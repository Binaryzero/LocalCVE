# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LocalCVE is a local-first, single-user application for tracking Common Vulnerabilities and Exposures (CVEs). It avoids external API dependencies by cloning and ingesting the CVEProject/cvelistV5 Git repository directly.

**Key Design Constraint**: Clean-room implementation inspired by OpenCVE, without using their code.

## Development Commands

### Running the Application

The application requires **two separate processes**:

1. **Backend Server** (Node.js):
   ```bash
   node src/server.js
   # Runs on http://127.0.0.1:17920
   ```

2. **Frontend Dev Server** (Vite):
   ```bash
   npm run dev
   # Runs on http://localhost:3000
   # Proxies /api requests to backend server
   ```

### Testing

```bash
# Unit tests (Jest)
npm test

# E2E tests (Playwright)
npm run e2e

# Build for production
npm run build
npm run preview
```

### Running a Single Test

```bash
# Jest unit test
NODE_OPTIONS=--experimental-vm-modules npx jest tests/unit/db.test.ts

# Playwright E2E test
npx playwright test tests/e2e/app.spec.ts
```

## Architecture

### Two-Server Design

1. **Backend** (`src/server.js`): Native Node.js HTTP server (no Express/Fastify)
   - Port: 17920
   - Handles all `/api/*` endpoints
   - Direct SQLite access via better-sqlite3
   - CORS enabled for local development

2. **Frontend**: React 19 SPA with Vite
   - Port: 3000
   - Vite proxies `/api` requests to backend
   - Single-page application mounted in `index.tsx`

### Data Flow

```
Git Repo (CVEProject/cvelistV5)
    ↓ [git clone/pull]
data/cvelistV5/
    ↓ [File system walk + JSON parse]
SQLite Database (cve.sqlite)
    ↓ [HTTP API]
React Frontend
```

### CVE Ingestion Strategy

**Initial Setup**: `git clone --depth 1` of cvelistV5 repository
**Updates**: `git pull` followed by `git diff --name-only` to identify changed files
**Processing**:
- Generator-based file walking to avoid loading all 320k+ paths into memory
- Batch inserts (2000 CVEs per transaction) for SQLite performance
- Computes SHA-256 hash of normalized CVE data to detect changes
- Stores change diffs in `cve_changes` table for audit trail

### Database Architecture

**File**: `cve.sqlite` in project root
**Mode**: WAL (Write-Ahead Logging) for better concurrent read/write
**Search**: FTS5 (Full-Text Search) virtual table for description and references

**Core Tables**:
- `cves`: Main CVE data (id, description, published, json blob)
- `metrics`: CVSS scores (V2, V3.0, V3.1) and severity ratings
- `cve_references`: URLs associated with CVEs
- `configs`: Affected products/configurations
- `job_runs`: Ingestion history and status
- `watchlists`: User-defined queries for alerting
- `alerts`: Generated matches between CVEs and watchlists
- `cve_changes`: Diff history for changed CVEs
- `system_metadata`: Key-value store for Git commit hashes
- `cves_fts`: Virtual FTS5 table for full-text search

**Schema Initialization**: Handled automatically in `src/lib/db.js` on first run

## Key Technical Details

### Frontend Stack

- **React 19** (latest) with ESM imports
- **Styling**: Tailwind CSS via CDN (see `index.html`)
- **Icons**: Lucide React
- **Charts**: Recharts for data visualization
- **State**: Plain `useState`/`useEffect` with fetch API
- **TypeScript**: Configured but .jsx components coexist with .tsx

### Backend Patterns

**No Framework**: Uses native `node:http` module directly
**Routing**: Manual pathname matching in `handleRequest()` function
**CORS**: Configured for development (`Access-Control-Allow-Origin: *`)
**Error Handling**: Centralized `sendJson()` and `sendError()` helpers with cache-control headers

### File Organization

```
src/
  server.js           # HTTP server and API routes
  lib/
    db.js             # SQLite initialization and schema
    ingest/
      nvd.js          # CVE ingestion from Git repository
    matcher.js        # Watchlist query matching logic
components/           # React components (.tsx)
tests/
  unit/              # Jest tests
  e2e/               # Playwright tests
```

### Search Implementation

The `/api/cves` endpoint supports:
- **Full-text search**: Uses FTS5 via `cves_fts` table (searches description + refs)
- **CVSS filtering**: `cvss_min` parameter for minimum score
- **Severity filtering**: Filter by LOW/MEDIUM/HIGH/CRITICAL
- **Pagination**: `limit` and `offset` parameters (default limit: 100)

FTS5 query formatting in `server.js` wraps terms in quotes and escapes special chars to avoid syntax errors with CVE IDs containing hyphens.

## Known Limitations & Roadmap

### Critical Missing Features

1. **Alert Generation**: The ingestion process saves CVEs but doesn't check against `watchlists` to populate the `alerts` table. This logic needs implementation in `src/lib/ingest/nvd.js`.

2. **EPSS Integration**: Database schema supports `epssScore` field, but no ingestion source exists yet.

### UI Limitations

- CVE list hard-limited to 100 items (pagination needed)
- No detailed CVE view (clicking CVE doesn't show full data)
- Search is client-side only; FTS5 not exposed via API parameters yet

## Development Workflow

1. Start backend server first: `node src/server.js`
2. Start Vite dev server: `npm run dev`
3. Access application at `http://localhost:3000`
4. Trigger CVE ingestion via Jobs tab in UI (POSTs to `/api/ingest`)
5. Monitor ingestion via job status table

## Data Sources

- **Primary**: CVEProject/cvelistV5 GitHub repository (JSON 5.0 format)
- **Location**: `data/cvelistV5/` (git clone)
- **Update Strategy**: Git pull + incremental diff processing
- **Fallback**: Full repository scan if diff fails

## Type System

TypeScript configuration uses ESNext modules with bundler resolution. The `@/*` path alias resolves to project root. JSX is set to `react-jsx` (automatic runtime). The project allows `.js` files alongside `.ts`/`.tsx`.
