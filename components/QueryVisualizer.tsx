import React from 'react';
import { Search, Shield, Calendar, AlertTriangle, TrendingUp, Building2, Package } from 'lucide-react';
import { QueryModel } from '../types';

interface QueryVisualizerProps {
  query: QueryModel;
  onChipClick?: (filter: Partial<QueryModel>) => void;
  compact?: boolean;
}

interface FilterChip {
  id: string;
  label: string;
  value: string;
  color: 'cyan' | 'red' | 'orange' | 'green' | 'purple' | 'yellow';
  icon: React.ReactNode;
  filter: Partial<QueryModel>;
}

const QueryVisualizer: React.FC<QueryVisualizerProps> = ({ query, onChipClick, compact = false }) => {
  const chips: FilterChip[] = [];

  // Text search
  if (query.text) {
    chips.push({
      id: 'text',
      label: 'Search',
      value: query.text.length > 20 ? query.text.substring(0, 20) + '...' : query.text,
      color: 'cyan',
      icon: <Search className="h-3 w-3" strokeWidth={1.5} />,
      filter: { text: query.text }
    });
  }

  // CVSS filters
  if (query.cvss_min !== undefined && query.cvss_min > 0) {
    const severity = getSeverityLabel(query.cvss_min);
    chips.push({
      id: 'cvss_min',
      label: 'CVSS',
      value: `>= ${query.cvss_min}${severity ? ` (${severity})` : ''}`,
      color: getCvssColor(query.cvss_min),
      icon: <Shield className="h-3 w-3" strokeWidth={1.5} />,
      filter: { cvss_min: query.cvss_min }
    });
  }

  if (query.cvss_max !== undefined && query.cvss_max < 10) {
    chips.push({
      id: 'cvss_max',
      label: 'CVSS',
      value: `<= ${query.cvss_max}`,
      color: getCvssColor(query.cvss_max),
      icon: <Shield className="h-3 w-3" strokeWidth={1.5} />,
      filter: { cvss_max: query.cvss_max }
    });
  }

  // Version-specific CVSS
  if (query.cvss2_min !== undefined && query.cvss2_min > 0) {
    chips.push({
      id: 'cvss2_min',
      label: 'CVSS 2.0',
      value: `>= ${query.cvss2_min}`,
      color: getCvssColor(query.cvss2_min),
      icon: <Shield className="h-3 w-3" strokeWidth={1.5} />,
      filter: { cvss2_min: query.cvss2_min }
    });
  }

  if (query.cvss30_min !== undefined && query.cvss30_min > 0) {
    chips.push({
      id: 'cvss30_min',
      label: 'CVSS 3.0',
      value: `>= ${query.cvss30_min}`,
      color: getCvssColor(query.cvss30_min),
      icon: <Shield className="h-3 w-3" strokeWidth={1.5} />,
      filter: { cvss30_min: query.cvss30_min }
    });
  }

  if (query.cvss31_min !== undefined && query.cvss31_min > 0) {
    chips.push({
      id: 'cvss31_min',
      label: 'CVSS 3.1',
      value: `>= ${query.cvss31_min}`,
      color: getCvssColor(query.cvss31_min),
      icon: <Shield className="h-3 w-3" strokeWidth={1.5} />,
      filter: { cvss31_min: query.cvss31_min }
    });
  }

  // Date filters - prefer showing relative labels when available
  if (query.published_relative) {
    // Show the relative preset label instead of absolute dates
    chips.push({
      id: 'published_relative',
      label: 'Published',
      value: getRelativeLabel(query.published_relative),
      color: 'purple',
      icon: <Calendar className="h-3 w-3" strokeWidth={1.5} />,
      filter: { published_relative: query.published_relative }
    });
  } else {
    if (query.published_from) {
      chips.push({
        id: 'published_from',
        label: 'Published',
        value: `after ${formatDate(query.published_from)}`,
        color: 'purple',
        icon: <Calendar className="h-3 w-3" strokeWidth={1.5} />,
        filter: { published_from: query.published_from }
      });
    }

    if (query.published_to) {
      chips.push({
        id: 'published_to',
        label: 'Published',
        value: `before ${formatDate(query.published_to)}`,
        color: 'purple',
        icon: <Calendar className="h-3 w-3" strokeWidth={1.5} />,
        filter: { published_to: query.published_to }
      });
    }
  }

  if (query.modified_relative) {
    // Show the relative preset label instead of absolute dates
    chips.push({
      id: 'modified_relative',
      label: 'Modified',
      value: getRelativeLabel(query.modified_relative),
      color: 'purple',
      icon: <Calendar className="h-3 w-3" strokeWidth={1.5} />,
      filter: { modified_relative: query.modified_relative }
    });
  } else {
    if (query.modified_from) {
      chips.push({
        id: 'modified_from',
        label: 'Modified',
        value: `after ${formatDate(query.modified_from)}`,
        color: 'purple',
        icon: <Calendar className="h-3 w-3" strokeWidth={1.5} />,
        filter: { modified_from: query.modified_from }
      });
    }

    if (query.modified_to) {
      chips.push({
        id: 'modified_to',
        label: 'Modified',
        value: `before ${formatDate(query.modified_to)}`,
        color: 'purple',
        icon: <Calendar className="h-3 w-3" strokeWidth={1.5} />,
        filter: { modified_to: query.modified_to }
      });
    }
  }

  // KEV flag
  if (query.kev === true) {
    chips.push({
      id: 'kev',
      label: 'KEV',
      value: 'Known Exploited',
      color: 'red',
      icon: <AlertTriangle className="h-3 w-3" strokeWidth={1.5} />,
      filter: { kev: true }
    });
  }

  // EPSS
  if (query.epss_min !== undefined && query.epss_min > 0) {
    chips.push({
      id: 'epss_min',
      label: 'EPSS',
      value: `>= ${(query.epss_min * 100).toFixed(1)}%`,
      color: 'yellow',
      icon: <TrendingUp className="h-3 w-3" strokeWidth={1.5} />,
      filter: { epss_min: query.epss_min }
    });
  }

  // Vendors
  if (query.vendors && query.vendors.length > 0) {
    query.vendors.forEach((vendor, index) => {
      chips.push({
        id: `vendor_${index}`,
        label: 'Vendor',
        value: vendor,
        color: 'cyan',
        icon: <Building2 className="h-3 w-3" strokeWidth={1.5} />,
        filter: { vendors: [vendor] }
      });
    });
  }

  // Products
  if (query.products && query.products.length > 0) {
    query.products.forEach((product, index) => {
      chips.push({
        id: `product_${index}`,
        label: 'Product',
        value: product,
        color: 'purple',
        icon: <Package className="h-3 w-3" strokeWidth={1.5} />,
        filter: { products: [product] }
      });
    });
  }

  if (chips.length === 0) {
    return (
      <div className="text-xs text-gray-500 mono italic">
        No filters defined
      </div>
    );
  }

  const colorClasses: Record<FilterChip['color'], string> = {
    cyan: 'bg-cyan-500/20 border-cyan-500/40 text-cyan-400',
    red: 'bg-red-500/20 border-red-500/40 text-red-400',
    orange: 'bg-orange-500/20 border-orange-500/40 text-orange-400',
    green: 'bg-green-500/20 border-green-500/40 text-green-400',
    purple: 'bg-purple-500/20 border-purple-500/40 text-purple-400',
    yellow: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-400'
  };

  if (compact) {
    // Compact mode: just show chip count
    return (
      <div className="flex items-center gap-2 text-xs text-gray-400 mono">
        <span className="px-2 py-0.5 rounded bg-gray-700 text-gray-300">
          {chips.length} filter{chips.length !== 1 ? 's' : ''}
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-wrap gap-2">
      {chips.map((chip) => (
        <button
          key={chip.id}
          onClick={() => onChipClick && onChipClick(chip.filter)}
          disabled={!onChipClick}
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs mono transition-all ${colorClasses[chip.color]} ${
            onChipClick ? 'hover:opacity-80 cursor-pointer' : 'cursor-default'
          }`}
          title={onChipClick ? `Click to search: ${chip.label} ${chip.value}` : `${chip.label}: ${chip.value}`}
        >
          {chip.icon}
          <span className="font-medium">{chip.label}</span>
          <span className="opacity-75">{chip.value}</span>
        </button>
      ))}
    </div>
  );
};

// Helper to get severity label from CVSS score
const getSeverityLabel = (score: number): string | null => {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  return null;
};

// Helper to get color based on CVSS score
const getCvssColor = (score: number): FilterChip['color'] => {
  if (score >= 9.0) return 'red';
  if (score >= 7.0) return 'orange';
  if (score >= 4.0) return 'yellow';
  return 'green';
};

// Helper to format date strings
const formatDate = (dateStr: string): string => {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });
};

// Helper to get human-readable label for relative date presets
const getRelativeLabel = (relative: string): string => {
  switch (relative) {
    case 'today': return 'Today';
    case 'last_7_days': return 'Last 7 Days';
    case 'last_30_days': return 'Last 30 Days';
    default: return relative;
  }
};

// Human-readable query summary (for accessibility or tooltips)
export const getQuerySummary = (query: QueryModel): string => {
  const parts: string[] = [];

  if (query.text) {
    parts.push(`containing "${query.text}"`);
  }

  if (query.cvss_min !== undefined && query.cvss_min > 0) {
    parts.push(`CVSS >= ${query.cvss_min}`);
  }

  if (query.cvss_max !== undefined && query.cvss_max < 10) {
    parts.push(`CVSS <= ${query.cvss_max}`);
  }

  if (query.kev) {
    parts.push('in KEV catalog');
  }

  if (query.published_from) {
    parts.push(`published after ${formatDate(query.published_from)}`);
  }

  if (query.published_to) {
    parts.push(`published before ${formatDate(query.published_to)}`);
  }

  if (query.epss_min !== undefined && query.epss_min > 0) {
    parts.push(`EPSS >= ${(query.epss_min * 100).toFixed(1)}%`);
  }

  if (query.vendors && query.vendors.length > 0) {
    parts.push(`vendor: ${query.vendors.join(', ')}`);
  }

  if (query.products && query.products.length > 0) {
    parts.push(`product: ${query.products.join(', ')}`);
  }

  return parts.length > 0 ? parts.join(' AND ') : 'All CVEs';
};

export default QueryVisualizer;
