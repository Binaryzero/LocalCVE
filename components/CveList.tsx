import React, { useState } from 'react';
import { Search, Filter, Save, ExternalLink, X, ChevronLeft, ChevronRight } from 'lucide-react';
import { Cve, QueryModel } from '../types';

interface CveListProps {
  cves: Cve[];
  onSaveWatchlist: (query: QueryModel) => void;
  filters: QueryModel;
  onFilterChange: (filters: QueryModel) => void;
  page: number;
  onPageChange: (page: number) => void;
  totalCount: number;
  pageSize: number;
  onSelectCve: (id: string) => void;
}

const CveList: React.FC<CveListProps> = ({
  cves,
  onSaveWatchlist,
  filters,
  onFilterChange,
  page,
  onPageChange,
  totalCount,
  pageSize,
  onSelectCve
}) => {
  const [showFilters, setShowFilters] = useState(false);

  const handleInputChange = (field: keyof QueryModel, value: any) => {
    onFilterChange({ ...filters, [field]: value });
    onPageChange(0);
  };

  const totalPages = Math.ceil(totalCount / pageSize);

  const getSeverityBadge = (severity: string | null, score: number | null) => {
    const configs = {
      'CRITICAL': { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
      'HIGH': { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' },
      'MEDIUM': { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30' },
      'LOW': { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30' },
    };
    const config = configs[severity as keyof typeof configs] || { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30' };

    return (
      <div className={`inline-flex items-center space-x-2 px-2.5 py-1 rounded border ${config.bg} ${config.border}`}>
        <span className={`text-xs font-bold mono ${config.text}`}>
          {score?.toFixed(1) || 'N/A'}
        </span>
        <span className={`text-xs mono ${config.text} opacity-70`}>
          {severity || 'UNK'}
        </span>
      </div>
    );
  };

  const hasActiveSearch = filters.text?.trim() || filters.cvss_min > 0 || filters.kev;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-100 mono tracking-tight">CVE SEARCH</h1>
          {hasActiveSearch && (
            <div className="flex items-center space-x-3 mt-2">
              <p className="text-sm text-gray-500 mono">
                {totalCount.toLocaleString()} <span className="text-gray-600">RESULTS</span>
              </p>
              <div className="w-1 h-1 bg-gray-600 rounded-full" />
              <p className="text-sm text-gray-500 mono">
                PAGE {page + 1}/{totalPages}
              </p>
            </div>
          )}
        </div>
        {hasActiveSearch && (
          <button
            onClick={() => onSaveWatchlist(filters)}
            className="inline-flex items-center px-4 py-2.5 rounded-lg border transition-all hover:border-cyan-500"
            style={{
              background: 'rgba(6, 182, 212, 0.1)',
              borderColor: 'var(--cyber-accent)',
              color: 'var(--cyber-accent)'
            }}
          >
            <Save className="h-4 w-4 mr-2" strokeWidth={1.5} />
            <span className="mono text-sm font-medium">CREATE WATCHLIST</span>
          </button>
        )}
      </div>

      {/* Search and Filters */}
      <div className="rounded-lg border p-4" style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        <div className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-500" strokeWidth={1.5} />
            <input
              type="text"
              placeholder="SEARCH CVE-ID OR DESCRIPTION..."
              className="w-full pl-12 pr-4 py-3 rounded-lg border bg-gray-900/50 text-gray-100 placeholder-gray-600 mono text-sm transition-all focus:outline-none focus:border-cyan-500"
              style={{ borderColor: 'var(--cyber-border)' }}
              value={filters.text || ''}
              onChange={(e) => handleInputChange('text', e.target.value)}
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center justify-center px-5 py-3 border rounded-lg mono text-sm font-medium transition-all ${
              showFilters
                ? 'bg-cyan-500/20 border-cyan-500 text-cyan-400'
                : 'border-gray-700 text-gray-400 hover:border-gray-600'
            }`}
          >
            <Filter className="h-4 w-4 mr-2" strokeWidth={1.5} />
            FILTERS
            {showFilters && <X className="h-4 w-4 ml-2" strokeWidth={1.5} />}
          </button>
        </div>

        {/* Filter Panel */}
        {showFilters && (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded-lg border" style={{
            background: 'rgba(6, 182, 212, 0.03)',
            borderColor: 'var(--cyber-border)'
          }}>
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-gray-400 mb-2 mono">MIN CVSS SCORE</label>
              <div className="flex items-center gap-4">
                <input
                  type="range"
                  min="0"
                  max="10"
                  step="1"
                  className="flex-1 h-2 rounded-lg appearance-none cursor-pointer"
                  style={{ background: 'var(--cyber-border)' }}
                  value={Math.floor(filters.cvss_min || 0)}
                  onChange={(e) => handleInputChange('cvss_min', parseFloat(e.target.value))}
                />
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  className="w-20 p-2.5 border rounded-lg bg-gray-900/50 text-gray-100 mono text-sm text-center focus:outline-none focus:border-cyan-500"
                  style={{ borderColor: 'var(--cyber-border)' }}
                  value={filters.cvss_min || 0}
                  onChange={(e) => handleInputChange('cvss_min', Math.min(10, Math.max(0, parseFloat(e.target.value) || 0)))}
                />
              </div>
            </div>
            <div className="flex items-end">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  className="w-4 h-4 rounded bg-gray-900 border-gray-700 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-0"
                  checked={filters.kev || false}
                  onChange={(e) => handleInputChange('kev', e.target.checked)}
                />
                <span className="text-sm text-gray-300 mono">KNOWN EXPLOITED (KEV)</span>
              </label>
            </div>
          </div>
        )}
      </div>

      {/* CVE Table */}
      <div className="rounded-lg border overflow-hidden" style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--cyber-border)' }}>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  CVE ID
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  SEVERITY
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  DESCRIPTION
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  PUBLISHED
                </th>
                <th className="px-6 py-4 text-center text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  REFS
                </th>
              </tr>
            </thead>
            <tbody>
              {!hasActiveSearch ? (
                <tr>
                  <td colSpan={5} className="px-6 py-20 text-center">
                    <div className="flex flex-col items-center space-y-4">
                      <div className="w-16 h-16 rounded-lg border border-cyan-500/30 flex items-center justify-center bg-cyan-500/5">
                        <Search className="h-8 w-8 text-cyan-400" strokeWidth={1.5} />
                      </div>
                      <div>
                        <p className="text-gray-300 mono text-sm font-medium mb-1">SEARCH THE CVE DATABASE</p>
                        <p className="text-gray-500 mono text-xs">Enter a CVE ID, keyword, or use filters to find vulnerabilities</p>
                      </div>
                    </div>
                  </td>
                </tr>
              ) : cves.length > 0 ? (
                cves.map((cve, index) => (
                  <tr
                    key={cve.id}
                    onClick={() => onSelectCve(cve.id)}
                    className="group cursor-pointer transition-all hover:bg-cyan-500/5"
                    style={{
                      borderBottom: index < cves.length - 1 ? '1px solid var(--cyber-border)' : 'none'
                    }}
                  >
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-bold text-cyan-400 mono group-hover:text-cyan-300 transition-colors">
                          {cve.id}
                        </span>
                        {cve.kev && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30 mono">
                            KEV
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getSeverityBadge(cve.cvssV3Severity, cve.cvssV3Score)}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400 max-w-2xl">
                      <div className="line-clamp-2 leading-relaxed">{cve.description}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 mono">
                      {new Date(cve.published).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit'
                      }).replace(/\//g, '-')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-center">
                      {cve.references.length > 0 && (
                        <a
                          href={cve.references[0]}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center justify-center w-8 h-8 rounded-lg border border-gray-700 text-gray-500 hover:border-cyan-500 hover:text-cyan-400 transition-all"
                        >
                          <ExternalLink className="h-4 w-4" strokeWidth={1.5} />
                        </a>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="px-6 py-16 text-center">
                    <div className="flex flex-col items-center space-y-3">
                      <div className="w-12 h-12 rounded-lg border border-gray-700 flex items-center justify-center">
                        <Search className="h-6 w-6 text-gray-600" strokeWidth={1.5} />
                      </div>
                      <p className="text-gray-500 mono text-sm">NO RESULTS MATCH YOUR SEARCH</p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-6 py-4 flex items-center justify-between border-t" style={{
            borderColor: 'var(--cyber-border)',
            background: 'rgba(6, 182, 212, 0.02)'
          }}>
            <div className="text-sm text-gray-400 mono">
              SHOWING {page * pageSize + 1}-{Math.min((page + 1) * pageSize, totalCount)} OF {totalCount}
            </div>
            <div className="flex gap-2">
              <button
                disabled={page === 0}
                onClick={() => onPageChange(page - 1)}
                className="inline-flex items-center px-4 py-2 border rounded-lg text-sm mono font-medium transition-all disabled:opacity-30 disabled:cursor-not-allowed hover:border-cyan-500 hover:text-cyan-400"
                style={{
                  borderColor: 'var(--cyber-border)',
                  color: 'var(--cyber-text-dim)'
                }}
              >
                <ChevronLeft className="h-4 w-4 mr-1" strokeWidth={1.5} />
                PREV
              </button>
              <button
                disabled={page >= totalPages - 1}
                onClick={() => onPageChange(page + 1)}
                className="inline-flex items-center px-4 py-2 border rounded-lg text-sm mono font-medium transition-all disabled:opacity-30 disabled:cursor-not-allowed hover:border-cyan-500 hover:text-cyan-400"
                style={{
                  borderColor: 'var(--cyber-border)',
                  color: 'var(--cyber-text-dim)'
                }}
              >
                NEXT
                <ChevronRight className="h-4 w-4 ml-1" strokeWidth={1.5} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CveList;
