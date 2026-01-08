import React, { useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip } from 'recharts';
import { Shield, AlertTriangle, Info, Zap, Target } from 'lucide-react';

interface CvssMetric {
  cvss_version: string;
  score: number;
  severity: string;
  vector_string: string | null;
}

interface SsvcData {
  exploitation: string;
  automatable: string;
  technical_impact: string;
  provider: string;
}

interface CvssVersionTabsProps {
  metrics: CvssMetric[];
  kev?: boolean;
  ssvc?: SsvcData[];
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

// SSVC severity colors
const getSsvcColor = (type: string, value: string | null) => {
  if (!value) return '#6b7280';
  const v = value.toLowerCase();
  if (type === 'exploitation') {
    if (v === 'active') return '#ef4444';
    if (v === 'poc') return '#f59e0b';
    return '#10b981';
  }
  if (type === 'automatable') {
    return v === 'yes' ? '#ef4444' : '#10b981';
  }
  if (type === 'technicalImpact') {
    return v === 'total' ? '#ef4444' : '#f59e0b';
  }
  return '#6b7280';
};

const CvssVersionTabs: React.FC<CvssVersionTabsProps> = ({ metrics, kev, ssvc }) => {
  // Build available versions from metrics array (single source of truth)
  const availableVersions: { version: string; score: number; severity: string; vectorString: string | null }[] = [];

  if (metrics && metrics.length > 0) {
    for (const m of metrics) {
      availableVersions.push({
        version: m.cvss_version,
        score: m.score,
        severity: m.severity,
        vectorString: m.vector_string
      });
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

      {/* Version Comparison Chart - only show if multiple versions */}
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

      {/* CISA Indicators - KEV and SSVC */}
      {(kev || (ssvc && ssvc.length > 0)) && (
        <div className="flex flex-wrap gap-3">
          {/* KEV Indicator */}
          {kev && (
            <div className="px-4 py-2.5 rounded-lg border mono text-sm font-medium border-red-500 bg-red-500/10 text-red-400">
              <span className="flex items-center gap-2">
                <Shield className="h-4 w-4" strokeWidth={1.5} />
                CISA KEV
                <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400">
                  EXPLOITED
                </span>
              </span>
            </div>
          )}

          {/* SSVC Indicators */}
          {ssvc && ssvc.length > 0 && ssvc.map((s, i) => (
            <React.Fragment key={i}>
              <div
                className="px-4 py-2.5 rounded-lg border mono text-sm font-medium"
                style={{
                  backgroundColor: `${getSsvcColor('exploitation', s.exploitation)}10`,
                  borderColor: `${getSsvcColor('exploitation', s.exploitation)}40`,
                  color: getSsvcColor('exploitation', s.exploitation)
                }}
              >
                <span className="flex items-center gap-2">
                  <Zap className="h-4 w-4" strokeWidth={1.5} />
                  Exploitation
                  <span
                    className="px-2 py-0.5 rounded text-xs font-bold"
                    style={{ backgroundColor: `${getSsvcColor('exploitation', s.exploitation)}20` }}
                  >
                    {s.exploitation?.toUpperCase() || 'UNKNOWN'}
                  </span>
                </span>
              </div>
              <div
                className="px-4 py-2.5 rounded-lg border mono text-sm font-medium"
                style={{
                  backgroundColor: `${getSsvcColor('automatable', s.automatable)}10`,
                  borderColor: `${getSsvcColor('automatable', s.automatable)}40`,
                  color: getSsvcColor('automatable', s.automatable)
                }}
              >
                <span className="flex items-center gap-2">
                  <Target className="h-4 w-4" strokeWidth={1.5} />
                  Automatable
                  <span
                    className="px-2 py-0.5 rounded text-xs font-bold"
                    style={{ backgroundColor: `${getSsvcColor('automatable', s.automatable)}20` }}
                  >
                    {s.automatable?.toUpperCase() || 'UNKNOWN'}
                  </span>
                </span>
              </div>
              <div
                className="px-4 py-2.5 rounded-lg border mono text-sm font-medium"
                style={{
                  backgroundColor: `${getSsvcColor('technicalImpact', s.technical_impact)}10`,
                  borderColor: `${getSsvcColor('technicalImpact', s.technical_impact)}40`,
                  color: getSsvcColor('technicalImpact', s.technical_impact)
                }}
              >
                <span className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" strokeWidth={1.5} />
                  Impact
                  <span
                    className="px-2 py-0.5 rounded text-xs font-bold"
                    style={{ backgroundColor: `${getSsvcColor('technicalImpact', s.technical_impact)}20` }}
                  >
                    {s.technical_impact?.toUpperCase() || 'UNKNOWN'}
                  </span>
                </span>
              </div>
            </React.Fragment>
          ))}
        </div>
      )}

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
