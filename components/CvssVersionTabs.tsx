import React, { useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip } from 'recharts';
import { Shield, AlertTriangle, Info } from 'lucide-react';

interface CvssMetric {
  cvss_version: string;
  score: number;
  severity: string;
  vector_string: string | null;
}

interface CvssVersionTabsProps {
  metrics: CvssMetric[];
  cvss2Score?: number | null;
  cvss2Severity?: string | null;
  cvss30Score?: number | null;
  cvss30Severity?: string | null;
  cvss31Score?: number | null;
  cvss31Severity?: string | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  'CRITICAL': '#ef4444',
  'HIGH': '#f59e0b',
  'MEDIUM': '#eab308',
  'LOW': '#10b981',
  'NONE': '#6b7280'
};

const VERSION_LABELS: Record<string, string> = {
  '2.0': 'CVSS 2.0',
  '3.0': 'CVSS 3.0',
  '3.1': 'CVSS 3.1'
};

// CVSS v3.x vector components and their descriptions
const CVSS_V3_COMPONENTS: Record<string, { name: string; values: Record<string, string> }> = {
  'AV': {
    name: 'Attack Vector',
    values: { 'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical' }
  },
  'AC': {
    name: 'Attack Complexity',
    values: { 'L': 'Low', 'H': 'High' }
  },
  'PR': {
    name: 'Privileges Required',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'UI': {
    name: 'User Interaction',
    values: { 'N': 'None', 'R': 'Required' }
  },
  'S': {
    name: 'Scope',
    values: { 'U': 'Unchanged', 'C': 'Changed' }
  },
  'C': {
    name: 'Confidentiality',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'I': {
    name: 'Integrity',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'A': {
    name: 'Availability',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  }
};

const CvssVersionTabs: React.FC<CvssVersionTabsProps> = ({
  metrics,
  cvss2Score,
  cvss2Severity,
  cvss30Score,
  cvss30Severity,
  cvss31Score,
  cvss31Severity
}) => {
  // Build available versions from both sources
  const availableVersions: { version: string; score: number; severity: string; vectorString: string | null }[] = [];

  // First try metrics array
  if (metrics && metrics.length > 0) {
    for (const m of metrics) {
      availableVersions.push({
        version: m.cvss_version,
        score: m.score,
        severity: m.severity,
        vectorString: m.vector_string
      });
    }
  } else {
    // Fallback to individual fields
    if (cvss2Score !== null && cvss2Score !== undefined) {
      availableVersions.push({ version: '2.0', score: cvss2Score, severity: cvss2Severity || 'UNKNOWN', vectorString: null });
    }
    if (cvss30Score !== null && cvss30Score !== undefined) {
      availableVersions.push({ version: '3.0', score: cvss30Score, severity: cvss30Severity || 'UNKNOWN', vectorString: null });
    }
    if (cvss31Score !== null && cvss31Score !== undefined) {
      availableVersions.push({ version: '3.1', score: cvss31Score, severity: cvss31Severity || 'UNKNOWN', vectorString: null });
    }
  }

  // Sort by version (newest first)
  availableVersions.sort((a, b) => parseFloat(b.version) - parseFloat(a.version));

  const [activeTab, setActiveTab] = useState(availableVersions[0]?.version || '3.1');

  if (availableVersions.length === 0) {
    return (
      <div className="p-6 rounded-lg border text-center" style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        <AlertTriangle className="h-8 w-8 text-gray-500 mx-auto mb-3" strokeWidth={1.5} />
        <p className="text-gray-400 mono text-sm">NO CVSS SCORES AVAILABLE</p>
      </div>
    );
  }

  const activeMetric = availableVersions.find(v => v.version === activeTab) || availableVersions[0];

  // Parse vector string for display
  const parseVectorString = (vectorString: string | null): { key: string; label: string; value: string; fullValue: string }[] => {
    if (!vectorString) return [];

    // Remove CVSS:3.x/ prefix if present
    const cleanVector = vectorString.replace(/^CVSS:\d+\.\d+\//, '');
    const parts = cleanVector.split('/');

    return parts.map(part => {
      const [key, value] = part.split(':');
      const component = CVSS_V3_COMPONENTS[key];
      return {
        key,
        label: component?.name || key,
        value,
        fullValue: component?.values[value] || value
      };
    }).filter(p => p.key && p.value);
  };

  // Prepare chart data
  const chartData = availableVersions.map(v => ({
    name: VERSION_LABELS[v.version] || `CVSS ${v.version}`,
    score: v.score,
    severity: v.severity
  }));

  return (
    <div className="space-y-6">
      {/* Tabs */}
      <div className="flex flex-wrap gap-2">
        {availableVersions.map(v => (
          <button
            key={v.version}
            onClick={() => setActiveTab(v.version)}
            className={`px-4 py-2.5 rounded-lg border mono text-sm font-medium transition-all ${
              activeTab === v.version
                ? 'border-cyan-500 bg-cyan-500/10 text-cyan-400'
                : 'border-gray-700 text-gray-400 hover:border-gray-600'
            }`}
          >
            <span className="flex items-center gap-2">
              <Shield className="h-4 w-4" strokeWidth={1.5} />
              {VERSION_LABELS[v.version] || `CVSS ${v.version}`}
              <span
                className="px-2 py-0.5 rounded text-xs font-bold"
                style={{
                  backgroundColor: `${SEVERITY_COLORS[v.severity]}20`,
                  color: SEVERITY_COLORS[v.severity]
                }}
              >
                {v.score.toFixed(1)}
              </span>
            </span>
          </button>
        ))}
      </div>

      {/* Active Version Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Score Display */}
        <div className="p-6 rounded-lg border" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)'
        }}>
          <h3 className="text-sm font-semibold text-gray-400 mono mb-4">
            {VERSION_LABELS[activeMetric.version]} SCORE
          </h3>

          <div className="flex items-center gap-6">
            {/* Score Circle */}
            <div
              className="w-24 h-24 rounded-full flex items-center justify-center border-4"
              style={{
                borderColor: SEVERITY_COLORS[activeMetric.severity],
                backgroundColor: `${SEVERITY_COLORS[activeMetric.severity]}10`
              }}
            >
              <span
                className="text-3xl font-bold mono"
                style={{ color: SEVERITY_COLORS[activeMetric.severity] }}
              >
                {activeMetric.score.toFixed(1)}
              </span>
            </div>

            {/* Severity Badge */}
            <div>
              <div
                className="inline-flex items-center px-4 py-2 rounded-lg border text-lg font-bold mono"
                style={{
                  backgroundColor: `${SEVERITY_COLORS[activeMetric.severity]}20`,
                  borderColor: `${SEVERITY_COLORS[activeMetric.severity]}40`,
                  color: SEVERITY_COLORS[activeMetric.severity]
                }}
              >
                {activeMetric.severity}
              </div>
              <p className="text-xs text-gray-500 mono mt-2">
                {activeMetric.score >= 9.0 ? 'Immediate action required' :
                 activeMetric.score >= 7.0 ? 'High priority remediation' :
                 activeMetric.score >= 4.0 ? 'Schedule remediation' :
                 'Low priority'}
              </p>
            </div>
          </div>
        </div>

        {/* Version Comparison Chart */}
        {availableVersions.length > 1 && (
          <div className="p-6 rounded-lg border" style={{
            background: 'var(--cyber-surface)',
            borderColor: 'var(--cyber-border)'
          }}>
            <h3 className="text-sm font-semibold text-gray-400 mono mb-4">
              VERSION COMPARISON
            </h3>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={chartData} layout="vertical" margin={{ left: 60, right: 20 }}>
                <XAxis type="number" domain={[0, 10]} tick={{ fill: '#6b7280', fontSize: 11 }} />
                <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 11 }} width={60} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="bg-gray-900 border border-gray-700 rounded-lg p-3 shadow-lg">
                          <p className="text-cyan-400 mono text-sm font-medium">{data.name}</p>
                          <p className="text-gray-300 mono text-xs">Score: {data.score.toFixed(1)}</p>
                          <p className="text-gray-400 mono text-xs">Severity: {data.severity}</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Vector String Breakdown */}
      {activeMetric.vectorString && (
        <div className="p-6 rounded-lg border" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)'
        }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-400 mono flex items-center gap-2">
              <Info className="h-4 w-4" strokeWidth={1.5} />
              VECTOR STRING
            </h3>
            <code className="text-xs text-cyan-400 mono bg-cyan-500/10 px-3 py-1.5 rounded-lg">
              {activeMetric.vectorString}
            </code>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {parseVectorString(activeMetric.vectorString).map(({ key, label, value, fullValue }) => (
              <div
                key={key}
                className="p-3 rounded-lg border"
                style={{
                  background: 'rgba(6, 182, 212, 0.03)',
                  borderColor: 'var(--cyber-border)'
                }}
              >
                <p className="text-xs text-gray-500 mono mb-1">{label}</p>
                <p className="text-sm text-gray-200 mono font-medium">
                  {fullValue}
                  <span className="text-cyan-400 ml-1">({value})</span>
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default CvssVersionTabs;
