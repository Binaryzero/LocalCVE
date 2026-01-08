import React from 'react';
import { Check } from 'lucide-react';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
const CVSS_VERSIONS = ['3.1', '3.0', '2.0'] as const;

type Severity = typeof SEVERITIES[number];
type CvssVersion = typeof CVSS_VERSIONS[number];

export interface SeverityMatrixSelection {
  // Key format: "SEVERITY_VERSION" e.g., "CRITICAL_3.1"
  selected: Set<string>;
}

interface SeverityMatrixProps {
  selection: SeverityMatrixSelection;
  onChange: (selection: SeverityMatrixSelection) => void;
}

const getCellKey = (severity: Severity, version: CvssVersion): string => {
  return `${severity}_${version}`;
};

const parseCellKey = (key: string): { severity: Severity; version: CvssVersion } | null => {
  const [severity, version] = key.split('_');
  if (SEVERITIES.includes(severity as Severity) && CVSS_VERSIONS.includes(version as CvssVersion)) {
    return { severity: severity as Severity, version: version as CvssVersion };
  }
  return null;
};

const getSeverityColor = (severity: Severity): string => {
  switch (severity) {
    case 'CRITICAL': return 'bg-red-500';
    case 'HIGH': return 'bg-orange-500';
    case 'MEDIUM': return 'bg-yellow-500';
    case 'LOW': return 'bg-green-500';
  }
};

const getSeverityBgColor = (severity: Severity, selected: boolean): string => {
  if (!selected) return 'bg-gray-800/50';
  switch (severity) {
    case 'CRITICAL': return 'bg-red-500/20 border-red-500/50';
    case 'HIGH': return 'bg-orange-500/20 border-orange-500/50';
    case 'MEDIUM': return 'bg-yellow-500/20 border-yellow-500/50';
    case 'LOW': return 'bg-green-500/20 border-green-500/50';
  }
};

const getSeverityRange = (severity: Severity): { min: number; max: number } => {
  switch (severity) {
    case 'CRITICAL': return { min: 9.0, max: 10.0 };
    case 'HIGH': return { min: 7.0, max: 8.9 };
    case 'MEDIUM': return { min: 4.0, max: 6.9 };
    case 'LOW': return { min: 0.1, max: 3.9 };
  }
};

const SeverityMatrix: React.FC<SeverityMatrixProps> = ({ selection, onChange }) => {
  const toggleCell = (severity: Severity, version: CvssVersion) => {
    const key = getCellKey(severity, version);
    const newSelected = new Set(selection.selected);
    if (newSelected.has(key)) {
      newSelected.delete(key);
    } else {
      newSelected.add(key);
    }
    onChange({ selected: newSelected });
  };

  const toggleRow = (severity: Severity) => {
    const rowKeys = CVSS_VERSIONS.map(v => getCellKey(severity, v));
    const allSelected = rowKeys.every(k => selection.selected.has(k));
    const newSelected = new Set(selection.selected);

    if (allSelected) {
      // Deselect all in row
      rowKeys.forEach(k => newSelected.delete(k));
    } else {
      // Select all in row
      rowKeys.forEach(k => newSelected.add(k));
    }
    onChange({ selected: newSelected });
  };

  const toggleColumn = (version: CvssVersion) => {
    const colKeys = SEVERITIES.map(s => getCellKey(s, version));
    const allSelected = colKeys.every(k => selection.selected.has(k));
    const newSelected = new Set(selection.selected);

    if (allSelected) {
      // Deselect all in column
      colKeys.forEach(k => newSelected.delete(k));
    } else {
      // Select all in column
      colKeys.forEach(k => newSelected.add(k));
    }
    onChange({ selected: newSelected });
  };

  const selectAll = () => {
    const allKeys = SEVERITIES.flatMap(s => CVSS_VERSIONS.map(v => getCellKey(s, v)));
    onChange({ selected: new Set(allKeys) });
  };

  const selectNone = () => {
    onChange({ selected: new Set() });
  };

  const isRowFullySelected = (severity: Severity): boolean => {
    return CVSS_VERSIONS.every(v => selection.selected.has(getCellKey(severity, v)));
  };

  const isRowPartiallySelected = (severity: Severity): boolean => {
    const count = CVSS_VERSIONS.filter(v => selection.selected.has(getCellKey(severity, v))).length;
    return count > 0 && count < CVSS_VERSIONS.length;
  };

  const isColFullySelected = (version: CvssVersion): boolean => {
    return SEVERITIES.every(s => selection.selected.has(getCellKey(s, version)));
  };

  const isColPartiallySelected = (version: CvssVersion): boolean => {
    const count = SEVERITIES.filter(s => selection.selected.has(getCellKey(s, version))).length;
    return count > 0 && count < SEVERITIES.length;
  };

  const anySelected = selection.selected.size > 0;

  return (
    <div className="space-y-2">
      {/* Header with quick actions */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500 mono font-semibold">SEVERITY MATRIX</span>
        <div className="flex items-center gap-2">
          {anySelected && (
            <button
              onClick={selectNone}
              className="text-xs text-gray-500 hover:text-gray-300 mono transition-colors"
            >
              CLEAR
            </button>
          )}
          <button
            onClick={selectAll}
            className="text-xs text-cyan-500 hover:text-cyan-400 mono transition-colors"
          >
            ALL
          </button>
        </div>
      </div>

      {/* Matrix Grid */}
      <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--cyber-border)' }}>
        {/* Header row with CVSS versions */}
        <div className="grid grid-cols-4 bg-gray-900/50">
          <div className="p-2" /> {/* Empty corner cell */}
          {CVSS_VERSIONS.map(version => (
            <button
              key={version}
              onClick={() => toggleColumn(version)}
              className={`p-2 text-center text-xs mono font-medium transition-colors ${
                isColFullySelected(version)
                  ? 'bg-cyan-500/20 text-cyan-400'
                  : isColPartiallySelected(version)
                  ? 'bg-cyan-500/10 text-cyan-500'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
              title={`Select all ${version}`}
            >
              v{version}
            </button>
          ))}
        </div>

        {/* Severity rows */}
        {SEVERITIES.map(severity => (
          <div key={severity} className="grid grid-cols-4 border-t" style={{ borderColor: 'var(--cyber-border)' }}>
            {/* Row header */}
            <button
              onClick={() => toggleRow(severity)}
              className={`p-2 flex items-center gap-2 text-xs mono font-medium transition-colors ${
                isRowFullySelected(severity)
                  ? 'bg-cyan-500/20 text-cyan-400'
                  : isRowPartiallySelected(severity)
                  ? 'bg-cyan-500/10 text-cyan-500'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
              title={`Select all ${severity}`}
            >
              <div className={`w-2 h-2 rounded-full ${getSeverityColor(severity)}`} />
              {severity.charAt(0) + severity.slice(1).toLowerCase()}
            </button>

            {/* Cells */}
            {CVSS_VERSIONS.map(version => {
              const key = getCellKey(severity, version);
              const isSelected = selection.selected.has(key);
              return (
                <button
                  key={key}
                  onClick={() => toggleCell(severity, version)}
                  className={`p-2 flex items-center justify-center border-l transition-all ${
                    isSelected
                      ? getSeverityBgColor(severity, true)
                      : 'hover:bg-gray-700/50'
                  }`}
                  style={{ borderColor: 'var(--cyber-border)' }}
                  title={`${severity} - CVSS ${version} (${getSeverityRange(severity).min}-${getSeverityRange(severity).max})`}
                >
                  {isSelected && (
                    <Check className={`h-4 w-4 ${
                      severity === 'CRITICAL' ? 'text-red-400' :
                      severity === 'HIGH' ? 'text-orange-400' :
                      severity === 'MEDIUM' ? 'text-yellow-400' :
                      'text-green-400'
                    }`} strokeWidth={2} />
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </div>

      {/* Selection summary */}
      {anySelected && (
        <div className="text-xs text-gray-500 mono">
          {selection.selected.size} combination{selection.selected.size !== 1 ? 's' : ''} selected
        </div>
      )}
    </div>
  );
};

// Helper to convert matrix selection to query parameters
export const matrixToQueryParams = (selection: SeverityMatrixSelection): Record<string, string> => {
  const params: Record<string, string> = {};

  if (selection.selected.size === 0) return params;

  // Group by version
  const byVersion: Record<CvssVersion, Severity[]> = {
    '3.1': [],
    '3.0': [],
    '2.0': []
  };

  selection.selected.forEach(key => {
    const parsed = parseCellKey(key);
    if (parsed) {
      byVersion[parsed.version].push(parsed.severity);
    }
  });

  // For each version with selections, find the min/max CVSS that covers them
  Object.entries(byVersion).forEach(([version, severities]) => {
    if (severities.length === 0) return;

    // Find overall min and max across all selected severities
    let overallMin = 10;
    let overallMax = 0;

    severities.forEach(severity => {
      const range = getSeverityRange(severity);
      overallMin = Math.min(overallMin, range.min);
      overallMax = Math.max(overallMax, range.max);
    });

    // Map version to query param name
    const paramPrefix = version === '3.1' ? 'cvss31' : version === '3.0' ? 'cvss30' : 'cvss2';
    params[`${paramPrefix}_min`] = overallMin.toString();
    // Note: We don't set max because the API doesn't support version-specific max filtering
  });

  return params;
};

// Helper to check if matrix can represent a simple query
export const isSimpleQuery = (selection: SeverityMatrixSelection): boolean => {
  // Simple if only one version is selected, or all versions have same severities
  if (selection.selected.size === 0) return true;

  const byVersion: Record<CvssVersion, Set<Severity>> = {
    '3.1': new Set(),
    '3.0': new Set(),
    '2.0': new Set()
  };

  selection.selected.forEach(key => {
    const parsed = parseCellKey(key);
    if (parsed) {
      byVersion[parsed.version].add(parsed.severity);
    }
  });

  // Check if only one version has selections
  const activeVersions = Object.values(byVersion).filter(set => set.size > 0);
  return activeVersions.length <= 1;
};

export default SeverityMatrix;
