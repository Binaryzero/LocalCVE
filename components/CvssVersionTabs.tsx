import React, { useState } from 'react';
import { Shield, AlertTriangle, Info, Zap, Target, ChevronDown, ChevronUp } from 'lucide-react';

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
  '3.1': 'CVSS 3.1',
  '4.0': 'CVSS 4.0'
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

// CVSS v4.0 vector components and their descriptions
const CVSS_V4_COMPONENTS: Record<string, { name: string; values: Record<string, string> }> = {
  'AV': {
    name: 'Attack Vector',
    values: { 'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical' }
  },
  'AC': {
    name: 'Attack Complexity',
    values: { 'L': 'Low', 'H': 'High' }
  },
  'AT': {
    name: 'Attack Requirements',
    values: { 'N': 'None', 'P': 'Present' }
  },
  'PR': {
    name: 'Privileges Required',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'UI': {
    name: 'User Interaction',
    values: { 'N': 'None', 'P': 'Passive', 'A': 'Active' }
  },
  'VC': {
    name: 'Vuln Confidentiality',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'VI': {
    name: 'Vuln Integrity',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'VA': {
    name: 'Vuln Availability',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'SC': {
    name: 'Sub Confidentiality',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'SI': {
    name: 'Sub Integrity',
    values: { 'N': 'None', 'L': 'Low', 'H': 'High' }
  },
  'SA': {
    name: 'Sub Availability',
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
  const [showVectorDetails, setShowVectorDetails] = useState(false);

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

    // Detect CVSS version from prefix and select appropriate component map
    const isV4 = vectorString.startsWith('CVSS:4.0/');
    const componentMap = isV4 ? CVSS_V4_COMPONENTS : CVSS_V3_COMPONENTS;

    // Remove CVSS:X.X/ prefix if present
    const cleanVector = vectorString.replace(/^CVSS:\d+\.\d+\//, '');
    const parts = cleanVector.split('/');

    return parts.map(part => {
      const [key, value] = part.split(':');
      const component = componentMap[key];
      return {
        key,
        label: component?.name || key,
        value,
        fullValue: component?.values[value] || value
      };
    }).filter(p => p.key && p.value);
  };

  return (
    <div className="space-y-6">
      {/* All indicators on same row: CVSS tabs + KEV + SSVC */}
      <div className="flex flex-wrap gap-2">
        {/* CVSS Version Tabs */}
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

        {/* KEV Indicator - same row */}
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

        {/* SSVC Indicators - same row */}
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

      {/* Vector String - Collapsible */}
      {activeMetric.vectorString && (
        <div className="rounded-lg border" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)'
        }}>
          <button
            onClick={() => setShowVectorDetails(!showVectorDetails)}
            className="w-full flex items-center justify-between p-4 hover:bg-cyan-500/5 transition-colors"
          >
            <h3 className="text-sm font-semibold text-gray-400 mono flex items-center gap-2">
              <Info className="h-4 w-4" strokeWidth={1.5} />
              VECTOR STRING
            </h3>
            <div className="flex items-center gap-3">
              <code className="text-xs text-cyan-400 mono bg-cyan-500/10 px-3 py-1.5 rounded-lg">
                {activeMetric.vectorString}
              </code>
              {showVectorDetails ? (
                <ChevronUp className="h-4 w-4 text-gray-500" strokeWidth={1.5} />
              ) : (
                <ChevronDown className="h-4 w-4 text-gray-500" strokeWidth={1.5} />
              )}
            </div>
          </button>

          {showVectorDetails && (
            <div className="px-4 pb-4">
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
      )}
    </div>
  );
};

export default CvssVersionTabs;
