# CVE Tracker

A local-first application for tracking Common Vulnerabilities and Exposures (CVEs). Ingests directly from the CVEProject/cvelistV5 Git repository, avoiding external API dependencies.

## Features

- **Search-First Interface** - Full-text search across 250k+ CVEs with FTS5
- **Multi-Version CVSS Support** - Filter by CVSS 2.0, 3.0, and 3.1 scores
- **Watchlists** - Define custom queries to monitor specific vulnerability patterns
- **Alert Generation** - Automatic notifications when new CVEs match your watchlists
- **KEV Integration** - Filter for Known Exploited Vulnerabilities
- **Local Storage** - All data stored in SQLite, no cloud dependencies

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
- `cvss2_min` / `cvss30_min` / `cvss31_min` - Version-specific CVSS filters
- `severity` - LOW, MEDIUM, HIGH, or CRITICAL
- `kev` - Filter for Known Exploited Vulnerabilities
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

### Jobs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/jobs` | List ingestion jobs |
| POST | `/api/ingest` | Start CVE ingestion |

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

## Documentation

Comprehensive user guides are organized in the `docs/` directory:
- `user-guide/getting-started.md` - Setup and basic usage
- `user-guide/watchlists.md` - Creating and managing watchlists
- `user-guide/alert-management.md` - Handling alerts
- `admin-guide/ingestion-optimization.md` - Advanced ingestion configuration

## License

MIT
