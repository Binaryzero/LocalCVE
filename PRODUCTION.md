# Production Deployment Guide

## Quick Start

```bash
# Build the frontend
npm run build

# Start the production server
npm start
```

The application will be available at `http://127.0.0.1:17920`

## Architecture

### Production Mode (Single Server)
In production, a single Node.js process serves both:
- **API endpoints** at `/api/*`
- **Static frontend** from `dist/` directory

```
npm start
  └── Node.js server (port 17920)
       ├── /api/* → Backend routes
       └── /* → Static files from dist/
```

### Development Mode (Two Servers)
For hot module replacement during development:

```bash
# Terminal 1: Backend server
npm run dev:backend

# Terminal 2: Vite dev server (with HMR)
npm run dev
```

```
Terminal 1: npm run dev:backend
  └── Node.js server (port 17920)
       └── /api/* → Backend routes

Terminal 2: npm run dev
  └── Vite dev server (port 3000)
       ├── /* → Source files with HMR
       └── /api/* → Proxied to port 17920
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | - | Set to `production` to serve from dist/ |
| `PORT` | 17920 | Server port (optional) |

## Build Process

```bash
npm run build
```

This creates optimized assets in `dist/`:
- Minified JavaScript bundle (~244 KB)
- Processed HTML with production CDN links
- Build time: ~1 second

## Data Storage

All data is stored locally in SQLite:
- **Database**: `cve.sqlite` in project root
- **CVE Repository**: `data/cvelistV5/` (Git clone)

## First Run

1. Build the frontend: `npm run build`
2. Start the server: `npm start`
3. Navigate to Jobs tab and click "RUN INGESTION"
4. Wait for initial CVE import (~240k CVEs, ~30 minutes)

## Updating CVE Data

Run ingestion periodically to fetch new CVEs:
- Navigate to Jobs tab
- Click "RUN INGESTION"
- Incremental updates are fast (only new/changed CVEs)

## Troubleshooting

### "Cannot find module better-sqlite3"
```bash
npm rebuild better-sqlite3
```

### MIME type errors in browser
Ensure you're running with `npm start` (not manual `node src/server.js`)

### Database locked
Only one ingestion can run at a time. Wait for current job to complete.
