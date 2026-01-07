export interface Cve {
  id: string;
  description: string;
  // Primary score for backward compatibility
  cvssScore: number | null;
  cvssSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  cvssVersion: '2.0' | '3.0' | '3.1' | null;
  // Version-specific scores
  cvss2Score?: number | null;
  cvss2Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  cvss30Score?: number | null;
  cvss30Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  cvss31Score?: number | null;
  cvss31Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
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
  status: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  itemsProcessed: number;
  progressPercent: number;
  itemsAdded: number;
  itemsUpdated: number;
  itemsUnchanged: number;
  currentPhase: string | null;
  lastHeartbeat: string | null;
  totalFiles: number | null;
  error: string | null;
}

export interface JobLog {
  id: number;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR';
  message: string;
  metadata: Record<string, unknown> | null;
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
  cvss2_min?: number;
  cvss2_max?: number;
  cvss30_min?: number;
  cvss30_max?: number;
  cvss31_min?: number;
  cvss31_max?: number;
  kev?: boolean;
  epss_min?: number;
}

export interface FilterPreset {
  id: string;
  name: string;
  query: QueryModel;
  isBuiltIn?: boolean;
}