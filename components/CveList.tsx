import React, { useState, useRef, useMemo } from 'react';
import { Search, Filter, Save, ExternalLink, X, ChevronLeft, ChevronRight, Grid3X3, Eye, ChevronDown } from 'lucide-react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Cve, QueryModel, Watchlist } from '../types';
import FilterPresets from './FilterPresets';
import SeverityMatrix, { SeverityMatrixSelection, matrixToQueryParams } from './SeverityMatrix';
import VendorProductFilter from './VendorProductFilter';

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
  watchlists?: Watchlist[];
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
  onSelectCve,
  watchlists = []
}) => {
  const [showFilters, setShowFilters] = useState(false);
  const [showMatrix, setShowMatrix] = useState(false);
  const [matrixSelection, setMatrixSelection] = useState<SeverityMatrixSelection>({ selected: new Set() });
  const [showWatchlistDropdown, setShowWatchlistDropdown] = useState(false);
  const [selectedWatchlistId, setSelectedWatchlistId] = useState<string | null>(null);
  const parentRef = useRef<HTMLDivElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowWatchlistDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const selectedWatchlist = watchlists.find(w => w.id === selectedWatchlistId);

  const handleSelectWatchlist = (watchlist: Watchlist | null) => {
    if (watchlist) {
      setSelectedWatchlistId(watchlist.id);
      onFilterChange(watchlist.query);
      onPageChange(0);
    } else {
      setSelectedWatchlistId(null);
      onFilterChange({ text: '', cvss_min: 0, cvss_max: 10 });
      onPageChange(0);
    }
    setShowWatchlistDropdown(false);
  };

  // Virtual scrolling setup - renders only visible rows for better performance
  const rowVirtualizer = useVirtualizer({
    count: cves.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 72, // Estimated row height in pixels
    overscan: 5, // Number of items to render outside visible area
  });

  const handleInputChange = (field: keyof QueryModel, value: any) => {
    onFilterChange({ ...filters, [field]: value });
    onPageChange(0);
  };

  // Handle matrix selection changes
  const handleMatrixChange = (selection: SeverityMatrixSelection) => {
    setMatrixSelection(selection);
    // Convert matrix selection to query params and apply
    const params = matrixToQueryParams(selection);
    const newFilters = { ...filters };
    // Clear previous version-specific CVSS mins
    delete newFilters.cvss2_min;
    delete newFilters.cvss30_min;
    delete newFilters.cvss31_min;
    // Apply new ones from matrix
    if (params.cvss2_min) newFilters.cvss2_min = parseFloat(params.cvss2_min);
    if (params.cvss30_min) newFilters.cvss30_min = parseFloat(params.cvss30_min);
    if (params.cvss31_min) newFilters.cvss31_min = parseFloat(params.cvss31_min);
    onFilterChange(newFilters);
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

  const hasActiveSearch = filters.text?.trim() || filters.cvss_min > 0 || filters.kev || filters.published_from || filters.published_to || (filters.vendors && filters.vendors.length > 0) || (filters.products && filters.products.length > 0);

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

      {/* Filter Presets */}
      <div className="rounded-lg border p-4" style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        <FilterPresets
          currentFilters={filters}
          onApplyPreset={(query) => {
            onFilterChange(query);
            onPageChange(0);
          }}
        />
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

          {/* Watchlist Dropdown */}
          {watchlists.length > 0 && (
            <div className="relative" ref={dropdownRef}>
              <button
                onClick={() => setShowWatchlistDropdown(!showWatchlistDropdown)}
                className={`flex items-center justify-between px-4 py-3 border rounded-lg mono text-sm font-medium transition-all min-w-[180px] ${
                  selectedWatchlist
                    ? 'bg-cyan-500/20 border-cyan-500 text-cyan-400'
                    : 'border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center">
                  <Eye className="h-4 w-4 mr-2" strokeWidth={1.5} />
                  <span className="truncate max-w-[120px]">
                    {selectedWatchlist ? selectedWatchlist.name : 'WATCHLIST'}
                  </span>
                </div>
                <ChevronDown className={`h-4 w-4 ml-2 transition-transform ${showWatchlistDropdown ? 'rotate-180' : ''}`} strokeWidth={1.5} />
              </button>

              {showWatchlistDropdown && (
                <div
                  className="absolute top-full left-0 mt-1 w-full min-w-[220px] rounded-lg border overflow-hidden z-50"
                  style={{
                    background: 'var(--cyber-surface)',
                    borderColor: 'var(--cyber-border)'
                  }}
                >
                  {/* Clear Selection Option */}
                  <button
                    onClick={() => handleSelectWatchlist(null)}
                    className={`w-full px-4 py-2.5 text-left text-sm mono transition-all hover:bg-cyan-500/10 ${
                      !selectedWatchlist ? 'text-gray-500' : 'text-gray-400'
                    }`}
                  >
                    ALL CVEs
                  </button>
                  <div className="border-t" style={{ borderColor: 'var(--cyber-border)' }} />
                  {/* Watchlist Options */}
                  {watchlists.map(wl => (
                    <button
                      key={wl.id}
                      onClick={() => handleSelectWatchlist(wl)}
                      className={`w-full px-4 py-2.5 text-left text-sm mono transition-all hover:bg-cyan-500/10 flex items-center justify-between ${
                        selectedWatchlistId === wl.id
                          ? 'bg-cyan-500/10 text-cyan-400'
                          : 'text-gray-300'
                      }`}
                    >
                      <span className="truncate">{wl.name}</span>
                      {wl.matchCount > 0 && (
                        <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-gray-700 text-gray-400">
                          {wl.matchCount}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

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
          <button
            onClick={() => setShowMatrix(!showMatrix)}
            className={`flex items-center justify-center px-5 py-3 border rounded-lg mono text-sm font-medium transition-all ${
              showMatrix
                ? 'bg-cyan-500/20 border-cyan-500 text-cyan-400'
                : matrixSelection.selected.size > 0
                ? 'border-cyan-500/50 text-cyan-400/70 hover:border-cyan-500'
                : 'border-gray-700 text-gray-400 hover:border-gray-600'
            }`}
            title="Severity Matrix Filter"
          >
            <Grid3X3 className="h-4 w-4 mr-2" strokeWidth={1.5} />
            MATRIX
            {matrixSelection.selected.size > 0 && (
              <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-cyan-500/30 text-cyan-400">
                {matrixSelection.selected.size}
              </span>
            )}
          </button>
        </div>

        {/* Filter Panel */}
        {showFilters && (
          <div className="mt-4 space-y-4 p-4 rounded-lg border" style={{
            background: 'rgba(6, 182, 212, 0.03)',
            borderColor: 'var(--cyber-border)'
          }}>
            {/* Row 1: CVSS and KEV */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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

            {/* Row 2: Date Range */}
            <div className="pt-3 border-t" style={{ borderColor: 'var(--cyber-border)' }}>
              <label className="block text-xs font-semibold text-gray-400 mb-3 mono">PUBLISHED DATE RANGE</label>
              <div className="flex flex-wrap items-center gap-3">
                {/* Quick Presets */}
                <div className="flex gap-2">
                  {[
                    { label: '7D', days: 7 },
                    { label: '30D', days: 30 },
                    { label: '90D', days: 90 },
                    { label: 'YTD', days: -1 },
                  ].map(preset => {
                    const getPresetDates = () => {
                      const to = new Date();
                      let from: Date;
                      if (preset.days === -1) {
                        from = new Date(to.getFullYear(), 0, 1);
                      } else {
                        from = new Date(to);
                        from.setDate(from.getDate() - preset.days);
                      }
                      return {
                        from: from.toISOString().split('T')[0],
                        to: to.toISOString().split('T')[0]
                      };
                    };

                    const isActive = () => {
                      const { from, to } = getPresetDates();
                      return filters.published_from === from && filters.published_to === to;
                    };

                    return (
                      <button
                        key={preset.label}
                        onClick={() => {
                          const { from, to } = getPresetDates();
                          onFilterChange({
                            ...filters,
                            published_from: from,
                            published_to: to
                          });
                          onPageChange(0);
                        }}
                        className={`px-3 py-1.5 rounded-lg border mono text-xs font-medium transition-all ${
                          isActive()
                            ? 'border-cyan-500 bg-cyan-500/20 text-cyan-400'
                            : 'border-gray-700 text-gray-400 hover:border-gray-600'
                        }`}
                      >
                        {preset.label}
                      </button>
                    );
                  })}
                </div>

                {/* Divider */}
                <div className="h-6 w-px bg-gray-700" />

                {/* Date Inputs */}
                <div className="flex items-center gap-2">
                  <input
                    type="date"
                    className="p-2 border rounded-lg bg-gray-900/50 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                    style={{ borderColor: 'var(--cyber-border)' }}
                    value={filters.published_from || ''}
                    onChange={(e) => handleInputChange('published_from', e.target.value || undefined)}
                  />
                  <span className="text-gray-500 mono text-xs">TO</span>
                  <input
                    type="date"
                    className="p-2 border rounded-lg bg-gray-900/50 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                    style={{ borderColor: 'var(--cyber-border)' }}
                    value={filters.published_to || ''}
                    onChange={(e) => handleInputChange('published_to', e.target.value || undefined)}
                  />
                </div>

                {/* Clear Dates */}
                {(filters.published_from || filters.published_to) && (
                  <button
                    onClick={() => {
                      onFilterChange({
                        ...filters,
                        published_from: undefined,
                        published_to: undefined
                      });
                      onPageChange(0);
                    }}
                    className="px-2 py-1.5 rounded-lg border border-gray-700 text-gray-500 hover:text-gray-300 hover:border-gray-600 transition-all"
                  >
                    <X className="h-4 w-4" strokeWidth={1.5} />
                  </button>
                )}
              </div>
            </div>

            {/* Row 3: Vendor/Product Filter */}
            <div className="pt-3 border-t" style={{ borderColor: 'var(--cyber-border)' }}>
              <VendorProductFilter
                selectedVendors={filters.vendors || []}
                selectedProducts={filters.products || []}
                onVendorsChange={(vendors) => {
                  onFilterChange({ ...filters, vendors: vendors.length > 0 ? vendors : undefined });
                  onPageChange(0);
                }}
                onProductsChange={(products) => {
                  onFilterChange({ ...filters, products: products.length > 0 ? products : undefined });
                  onPageChange(0);
                }}
              />
            </div>
          </div>
        )}

        {/* Severity Matrix Panel */}
        {showMatrix && (
          <div className="mt-4 p-4 rounded-lg border" style={{
            background: 'rgba(6, 182, 212, 0.03)',
            borderColor: 'var(--cyber-border)'
          }}>
            <SeverityMatrix
              selection={matrixSelection}
              onChange={handleMatrixChange}
            />
            <p className="mt-3 text-xs text-gray-600 mono">
              Click cells to filter by severity and CVSS version. Click row/column headers to select entire rows or columns.
            </p>
          </div>
        )}
      </div>

      {/* CVE Table with Virtual Scrolling */}
      <div className="rounded-lg border overflow-hidden" style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        {/* Header Row - Fixed */}
        <div
          className="grid bg-gray-900/30"
          style={{
            gridTemplateColumns: '180px 140px 1fr 120px 80px',
            borderBottom: '1px solid var(--cyber-border)'
          }}
        >
          <div className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono">
            CVE ID
          </div>
          <div className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono">
            SEVERITY
          </div>
          <div className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono">
            DESCRIPTION
          </div>
          <div className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono">
            PUBLISHED
          </div>
          <div className="px-6 py-4 text-center text-xs font-semibold text-gray-500 uppercase tracking-wider mono">
            REFS
          </div>
        </div>

        {/* Body - Virtualized */}
        {!hasActiveSearch ? (
          <div className="px-6 py-20 text-center">
            <div className="flex flex-col items-center space-y-4">
              <div className="w-16 h-16 rounded-lg border border-cyan-500/30 flex items-center justify-center bg-cyan-500/5">
                <Search className="h-8 w-8 text-cyan-400" strokeWidth={1.5} />
              </div>
              <div>
                <p className="text-gray-300 mono text-sm font-medium mb-1">SEARCH THE CVE DATABASE</p>
                <p className="text-gray-500 mono text-xs">Enter a CVE ID, keyword, or use filters to find vulnerabilities</p>
              </div>
            </div>
          </div>
        ) : cves.length > 0 ? (
          <div
            ref={parentRef}
            className="overflow-auto"
            style={{ maxHeight: '600px' }}
          >
            <div
              style={{
                height: `${rowVirtualizer.getTotalSize()}px`,
                width: '100%',
                position: 'relative',
              }}
            >
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const cve = cves[virtualRow.index];
                const isLast = virtualRow.index === cves.length - 1;
                return (
                  <div
                    key={cve.id}
                    data-index={virtualRow.index}
                    ref={rowVirtualizer.measureElement}
                    className="grid group cursor-pointer transition-all hover:bg-cyan-500/5"
                    style={{
                      gridTemplateColumns: '180px 140px 1fr 120px 80px',
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      transform: `translateY(${virtualRow.start}px)`,
                      borderBottom: !isLast ? '1px solid var(--cyber-border)' : 'none'
                    }}
                    onClick={() => onSelectCve(cve.id)}
                  >
                    <div className="px-6 py-4 whitespace-nowrap">
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
                    </div>
                    <div className="px-6 py-4 whitespace-nowrap">
                      {getSeverityBadge(cve.cvssSeverity, cve.cvssScore)}
                    </div>
                    <div className="px-6 py-4 text-sm text-gray-400">
                      <div className="line-clamp-2 leading-relaxed">{cve.description}</div>
                    </div>
                    <div className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 mono">
                      {new Date(cve.published).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit'
                      }).replace(/\//g, '-')}
                    </div>
                    <div className="px-6 py-4 whitespace-nowrap text-center">
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
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="px-6 py-16 text-center">
            <div className="flex flex-col items-center space-y-3">
              <div className="w-12 h-12 rounded-lg border border-gray-700 flex items-center justify-center">
                <Search className="h-6 w-6 text-gray-600" strokeWidth={1.5} />
              </div>
              <p className="text-gray-500 mono text-sm">NO RESULTS MATCH YOUR SEARCH</p>
            </div>
          </div>
        )}

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
