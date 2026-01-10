# CVE Tracker

A local-first application for tracking Common Vulnerabilities and Exposures (CVEs). Ingests directly from the CVEProject/cvelistV5 Git repository, avoiding external API dependencies.

## Features

### Core Functionality
- **Search-First Interface** - Full-text search across 326k+ CVEs with FTS5
- **Multi-Version CVSS Support** - Filter by CVSS 2.0, 3.0, 3.1, and 4.0 scores
- **Watchlists** - Define custom queries to monitor specific vulnerability patterns
- **Alert Generation** - Automatic notifications when new CVEs match your watchlists
- **Local Storage** - All data stored in SQLite, no cloud dependencies

### Threat Intelligence Enrichment
- **CVSS-BT Integration** - EPSS scores, exploit maturity, and threat intel sources
- **Trickest PoC Links** - GitHub exploit repositories and security advisories
- **CISA KEV** - Known Exploited Vulnerabilities flagging

### Navigation & UI
- **Split Pane Layout** - Side-by-side CVE list and detail view
- **Prev/Next Navigation** - Browse CVEs with keyboard shortcuts (Arrow, J/K, Escape)
- **Sticky Scroll Position** - Return to your place in the list with highlight animation
- **Filter Presets** - Save and manage custom filter configurations
- **Settings Page** - Hide rejected/disputed CVEs, manage preferences

## Prerequisites

- Node.js 25.2.1
- npm >= 8.0.0
- SQLite3 (system dependency)

## Quick Start

```bash
# Install dependencies
npm install

# Build the frontend
npm run build

# Start the production server
npm start
```

The application will be available at `http://127.0.0.1:17920`

### First Run

1. Navigate to the **Ingestion** tab
2. Click **RUN INGESTION** to clone and process the CVE repository
3. Initial import requires 2GB disk space and processes ~250k CVEs (takes ~30 minutes)
4. Subsequent updates are incremental and fast

## Development

### Two-Server Mode (with Hot Reload)

```bash
# Terminal 1: Backend server
npm run dev:backend

# Terminal 2: Vite dev server with HMR
npm run dev
```

- Backend runs on port 17920
- Frontend runs on port 3000 (proxies API requests to backend)

### Testing

```bash
# Unit tests
npm test

# E2E tests (requires built frontend)
npm run build && npm run e2e

# Type checking
npx tsc --noEmit
```

## Architecture

### Production Mode

A single Node.js process serves both the API and static frontend:

```
npm start
  └── Node.js server (port 17920)
       ├── /api/* → Backend routes
       └── /* → Static files from dist/
```

### Data Flow

```
CVEProject/cvelistV5 (Git)
    ↓ git clone/pull
data/cvelistV5/
    ↓ JSON parsing + batch processing
SQLite (cve.sqlite)
    ↓ HTTP API
React Frontend
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, TypeScript, Tailwind CSS |
| Backend | Node.js (native HTTP, no framework) |
| Database | SQLite with FTS5, better-sqlite3 |
| Build | Vite |
| Testing | Jest (unit), Playwright (E2E) |

## API Endpoints

### CVEs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cves` | Search CVEs with filters |

Query parameters:
- `search` - Full-text search query
- `cvss_min` / `cvss_max` - CVSS score range (0-10)
- `cvss2_min` / `cvss30_min` / `cvss31_min` / `cvss40_min` - Version-specific CVSS filters
- `severity` - LOW, MEDIUM, HIGH, or CRITICAL
- `kev` - Filter for Known Exploited Vulnerabilities
- `vendors` / `products` - Comma-separated lists for affected software filtering
- `published_from` / `published_to` - Date range filters (ISO format)
- `modified_from` / `modified_to` - Modified date range filters
- `epss_min` - Minimum EPSS score (0-1)
- `exploit_maturity` - Filter by exploit maturity level
- `hide_rejected` / `hide_disputed` - Exclude rejected/disputed CVEs
- `sort_by` / `sort_order` - Column sorting (id, score, published; asc/desc)
- `limit` / `offset` - Pagination (default limit: 100, max: 1000)

### Watchlists

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/watchlists` | List all watchlists |
| POST | `/api/watchlists` | Create watchlist |
| PUT | `/api/watchlists/:id` | Update watchlist |
| DELETE | `/api/watchlists/:id` | Delete watchlist |

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List all alerts |
| PUT | `/api/alerts/:id/read` | Mark alert as read |
| DELETE | `/api/alerts/:id` | Delete alert |
| PUT | `/api/alerts/mark-all-read` | Mark all alerts read |
| DELETE | `/api/alerts/delete-all` | Delete all alerts |

### Jobs & Ingestion

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/jobs` | List ingestion jobs |
| POST | `/api/ingest` | Start CVE ingestion (incremental) |
| POST | `/api/ingest/bulk` | Start bulk ingestion (faster initial load) |
| POST | `/api/ingest/cvss-bt` | Sync CVSS-BT enrichment data |
| POST | `/api/ingest/trickest` | Sync Trickest PoC links |
| POST | `/api/jobs/:id/cancel` | Cancel running job |
| GET | `/api/jobs/:id/logs` | Get job logs |
| GET | `/api/jobs/:id/logs/stream` | SSE stream for real-time logs |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Database health and completeness |
| GET | `/api/vendors` | Typeahead for vendor filtering |
| GET | `/api/products` | Typeahead for product filtering |

## Data Storage

| Item | Location |
|------|----------|
| Database | `cve.sqlite` (project root) |
| CVE Repository | `data/cvelistV5/` |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | - | Set to `production` for optimized serving |
| `PORT` | 17920 | Server port |

## Troubleshooting

### "Cannot find module better-sqlite3"

```bash
npm rebuild better-sqlite3
```

### MIME type errors in browser

Ensure you're running with `npm start` (not manual `node src/server.js`)

### Database locked

Only one ingestion can run at a time. Wait for current job to complete.

## Security

This project follows security best practices documented in `.github/instructions/`:
- Input validation and injection defense (parameterized queries)
- API security (rate limiting, CORS, validation)
- Logging with redaction of sensitive data

## License

MIT
