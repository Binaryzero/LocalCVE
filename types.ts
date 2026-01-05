export interface Cve {
  id: string;
  description: string;
  cvssV3Score: number | null;
  cvssV3Severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  published: string;
  lastModified: string;
  epssScore: number | null;
  kev: boolean;
  references: string[];
}

export interface JobRun {
  id: number;
  startTime: string;
  endTime: string | null;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED';
  itemsProcessed: number;
  error: string | null;
}

export interface Watchlist {
  id: string;
  name: string;
  query: QueryModel;
  enabled: boolean;
  lastRun: string | null;
  matchCount: number;
}

export interface Alert {
  id: string;
  cveId: string;
  watchlistId: string;
  watchlistName: string;
  type: 'NEW_MATCH' | 'UPDATED_MATCH';
  createdAt: string;
  read: boolean;
}

export interface QueryModel {
  text?: string;
  published_from?: string;
  published_to?: string;
  modified_from?: string;
  modified_to?: string;
  cvss_min?: number;
  cvss_max?: number;
  kev?: boolean;
  epss_min?: number;
}