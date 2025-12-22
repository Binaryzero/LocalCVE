# Local CVE Tracker

A local-only, single-user CVE tracking application designed for privacy and reliability.

## Features

- **Local Data Source**: Ingests vulnerability data directly from the [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) GitHub repository (JSON 5.0 format). This eliminates reliance on rate-limited public APIs like NVD.
- **Incremental Updates**: Uses `git diff` to efficiently process only changed files after the initial clone.
- **Dashboard**: High-level overview of critical vulnerabilities and alert status.
- **Search & Filter**: Full-text search capability powered by SQLite FTS5.
- **Watchlists**: Define dynamic criteria (vendor, product, CVSS score) to track relevant CVEs.
- **Alerts**: Receive notifications when new or updated CVEs match your watchlists.

## Prerequisites

- **Node.js**: v18 or later.
- **Git**: Must be installed and available in your system `PATH`. The application uses the system `git` command to clone and update the data repository.

## Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the application:
   ```bash
   node src/server.js
   ```

## Usage

1. Open your browser and navigate to `http://127.0.0.1:3000`.
2. **First Run**:
   - Navigate to the **Jobs** tab.
   - Click **Run Ingestion**.
   - *Note*: The initial ingestion triggers a shallow clone of the `cvelistV5` repository. This downloads the entire CVE history and may take a few minutes depending on your internet connection.
3. **Subsequent Runs**:
   - Clicking **Run Ingestion** will perform a `git pull`.
   - The system detects changes between the previous and current commit to update only modified CVEs.

## Architecture

- **Backend**: Node.js (Vanilla `http` module).
- **Database**: SQLite (via `better-sqlite3`) utilizing WAL mode for concurrency and FTS5 for search.
- **Frontend**: React (No build step required; uses ESM imports via `index.html`).
- **Data Storage**:
  - SQLite DB: `cve.sqlite` (Root directory)
  - CVE Data Repo: `data/cvelistV5` (Cloned repository)
