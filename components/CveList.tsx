import React, { useState, useRef, useMemo, useEffect } from 'react';
import { Search, Filter, Save, X, ChevronLeft, ChevronRight, Eye, ChevronDown, ChevronsLeft, ChevronsRight, ChevronUp, ChevronsUpDown, Bookmark, Check, Columns, LayoutList } from 'lucide-react';
import { FilterPreset } from '../types';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Cve, QueryModel, Watchlist } from '../types';
import FilterPresets from './FilterPresets';
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
  onSelectCve: (id: string, scrollPosition?: number) => void;
  watchlists?: Watchlist[];
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  onSortChange?: (column: string, order: 'asc' | 'desc') => void;
  initialScrollPosition?: number;
  lastViewedCveId?: string | null;
  layoutMode?: 'list' | 'split';
  onToggleLayout?: () => void;
  selectedCveId?: string | null;
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
  watchlists = [],
  sortBy = 'published',
  sortOrder = 'desc',
  onSortChange,
  initialScrollPosition = 0,
  lastViewedCveId = null,
  layoutMode = 'list',
  onToggleLayout,
  selectedCveId = null
}) => {
  const isSplitMode = layoutMode === 'split';
  const [showFilters, setShowFilters] = useState(false);
  const [showWatchlistDropdown, setShowWatchlistDropdown] = useState(false);
  const [selectedWatchlistId, setSelectedWatchlistId] = useState<string | null>(null);
  const [showSavePresetDialog, setShowSavePresetDialog] = useState(false);
  const [newPresetName, setNewPresetName] = useState('');
  const parentRef = useRef<HTMLDivElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const [highlightedCveId, setHighlightedCveId] = useState<string | null>(null);

  const PRESET_STORAGE_KEY = 'localcve_filter_presets';

  // Restore scroll position when returning from detail view
  useEffect(() => {
    if (initialScrollPosition > 0 && parentRef.current) {
      // Small delay to ensure virtual list is rendered
      requestAnimationFrame(() => {
        if (parentRef.current) {
          parentRef.current.scrollTop = initialScrollPosition;
        }
      });
    }
  }, []); // Only run on mount

  // Highlight the last-viewed CVE temporarily when returning
  useEffect(() => {
    if (lastViewedCveId) {
      setHighlightedCveId(lastViewedCveId);
      // Clear highlight after animation completes
      const timer = setTimeout(() => setHighlightedCveId(null), 1500);
      return () => clearTimeout(timer);
    }
  }, [lastViewedCveId]);

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

  // Save current filters as a new preset
  const handleSavePreset = () => {
    if (!newPresetName.trim()) return;

    const newPreset: FilterPreset = {
      id: `custom_${Date.now()}`,
      name: newPresetName.trim(),
      query: { ...filters },
      isBuiltIn: false,
      color: 'cyan',
      icon: 'zap'
    };

    try {
      const stored = localStorage.getItem(PRESET_STORAGE_KEY);
      const existingPresets: FilterPreset[] = stored ? JSON.parse(stored) : [];
      const updatedPresets = [...existingPresets, newPreset];
      localStorage.setItem(PRESET_STORAGE_KEY, JSON.stringify(updatedPresets));
      // Notify FilterPresets component to reload
      window.dispatchEvent(new Event('presets-updated'));
    } catch (e) {
      console.error('Failed to save preset:', e);
    }

    setNewPresetName('');
    setShowSavePresetDialog(false);
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

  const totalPages = Math.ceil(totalCount / pageSize);

  // Generate visible page numbers for pagination
  const getVisiblePages = () => {
    const pages: number[] = [];
    const maxVisible = 5;

    if (totalPages <= maxVisible) {
      for (let i = 0; i < totalPages; i++) pages.push(i);
      return pages;
    }

    let start = Math.max(0, page - 2);
    let end = Math.min(totalPages - 1, start + maxVisible - 1);

    if (end - start < maxVisible - 1) {
      start = Math.max(0, end - maxVisible + 1);
    }

    for (let i = start; i <= end; i++) {
      pages.push(i);
    }
    return pages;
  };

  // Scroll to top of the CVE list
  const scrollToTop = () => {
    parentRef.current?.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Pagination controls component for reuse at top and bottom
  const PaginationControls = ({ position }: { position: 'top' | 'bottom' }) => {
    const handlePageChange = (newPage: number) => {
      onPageChange(newPage);
      if (position === 'bottom') {
        scrollToTop();
      }
    };

    return (
      <div className={`px-4 py-3 flex items-center justify-between flex-shrink-0 ${position === 'bottom' ? 'border-t' : 'border-b'}`} style={{
        borderColor: 'var(--cyber-border)',
        background: 'rgba(6, 182, 212, 0.02)'
      }}>
        <div className="text-xs text-gray-500 mono">
          {page * pageSize + 1}-{Math.min((page + 1) * pageSize, totalCount)} of {totalCount.toLocaleString()}
        </div>
        <div className="flex items-center gap-1">
          <button
            disabled={page === 0}
            onClick={() => handlePageChange(0)}
            className="p-2 border rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed hover:border-cyan-500 hover:text-cyan-400"
            style={{ borderColor: 'var(--cyber-border)', color: 'var(--cyber-text-dim)' }}
            title="First page"
          >
            <ChevronsLeft className="h-4 w-4" strokeWidth={1.5} />
          </button>
          <button
            disabled={page === 0}
            onClick={() => handlePageChange(page - 1)}
            className="p-2 border rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed hover:border-cyan-500 hover:text-cyan-400"
            style={{ borderColor: 'var(--cyber-border)', color: 'var(--cyber-text-dim)' }}
            title="Previous page"
          >
            <ChevronLeft className="h-4 w-4" strokeWidth={1.5} />
          </button>
          <div className="flex items-center gap-1 mx-1">
            {getVisiblePages()[0] > 0 && (
              <span className="px-1 text-gray-600 mono text-xs">...</span>
            )}
            {getVisiblePages().map(p => (
              <button
                key={p}
                onClick={() => handlePageChange(p)}
                className={`min-w-[32px] px-2 py-1.5 border rounded-lg mono text-xs font-medium transition-all ${
                  p === page
                    ? 'bg-cyan-500/20 border-cyan-500 text-cyan-400'
                    : 'border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-300'
                }`}
              >
                {p + 1}
              </button>
            ))}
            {getVisiblePages()[getVisiblePages().length - 1] < totalPages - 1 && (
              <span className="px-1 text-gray-600 mono text-xs">...</span>
            )}
          </div>
          <button
            disabled={page >= totalPages - 1}
            onClick={() => handlePageChange(page + 1)}
            className="p-2 border rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed hover:border-cyan-500 hover:text-cyan-400"
            style={{ borderColor: 'var(--cyber-border)', color: 'var(--cyber-text-dim)' }}
            title="Next page"
          >
            <ChevronRight className="h-4 w-4" strokeWidth={1.5} />
          </button>
          <button
            disabled={page >= totalPages - 1}
            onClick={() => handlePageChange(totalPages - 1)}
            className="p-2 border rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed hover:border-cyan-500 hover:text-cyan-400"
            style={{ borderColor: 'var(--cyber-border)', color: 'var(--cyber-text-dim)' }}
            title="Last page"
          >
            <ChevronsRight className="h-4 w-4" strokeWidth={1.5} />
          </button>
        </div>
      </div>
    );
  };

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

  const hasActiveSearch = filters.text?.trim() || filters.cvss_min > 0 || filters.kev || filters.epss_min || filters.exploit_maturity || filters.published_from || filters.published_to || filters.published_relative || filters.modified_from || filters.modified_to || filters.modified_relative || (filters.vendors && filters.vendors.length > 0) || (filters.products && filters.products.length > 0);

  // Sortable column header component
  const SortableHeader = ({
    label,
    column,
  }: {
    label: string;
    column: string;
  }) => {
    const isActive = sortBy === column;

    const handleClick = () => {
      if (!onSortChange) return;
      if (isActive) {
        // Toggle direction
        onSortChange(column, sortOrder === 'asc' ? 'desc' : 'asc');
      } else {
        // New column, default desc (newest/highest first)
        onSortChange(column, 'desc');
      }
    };

    return (
      <button
        onClick={handleClick}
        className={`px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider mono flex items-center gap-1 hover:text-cyan-400 transition-colors w-full ${
          isActive ? 'text-cyan-400' : 'text-gray-500'
        }`}
      >
        {label}
        {isActive ? (
          sortOrder === 'asc'
            ? <ChevronUp className="h-3 w-3" />
            : <ChevronDown className="h-3 w-3" />
        ) : (
          <ChevronsUpDown className="h-3 w-3 opacity-30" />
        )}
      </button>
    );
  };

  return (
    <div className={isSplitMode ? "space-y-3 h-full flex flex-col" : "space-y-6"}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex items-center gap-4">
          <div>
            <h1 className={`font-bold text-gray-100 mono tracking-tight ${isSplitMode ? 'text-xl' : 'text-3xl'}`}>
              {isSplitMode ? 'CVEs' : 'CVE SEARCH'}
            </h1>
            {hasActiveSearch && (
              <div className="flex items-center space-x-3 mt-1">
                <p className="text-xs text-gray-500 mono">
                  {totalCount.toLocaleString()} <span className="text-gray-600">RESULTS</span>
                </p>
                <div className="w-1 h-1 bg-gray-600 rounded-full" />
                <p className="text-xs text-gray-500 mono">
                  PAGE {page + 1}/{totalPages}
                </p>
              </div>
            )}
          </div>
          {/* Layout toggle button */}
          {onToggleLayout && (
            <button
              onClick={onToggleLayout}
              className={`p-2 rounded-lg border transition-all ${
                isSplitMode
                  ? 'bg-cyan-500/20 border-cyan-500 text-cyan-400'
                  : 'border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-300'
              }`}
              title={isSplitMode ? 'Switch to list view' : 'Switch to split pane view'}
            >
              {isSplitMode ? (
                <LayoutList className="h-4 w-4" strokeWidth={1.5} />
              ) : (
                <Columns className="h-4 w-4" strokeWidth={1.5} />
              )}
            </button>
          )}
        </div>
        {hasActiveSearch && !isSplitMode && (
          <div className="flex items-center gap-2">
            {/* Save Preset Dialog */}
            {showSavePresetDialog ? (
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Preset name..."
                  className="px-3 py-2 rounded-lg border bg-gray-900/50 text-gray-100 placeholder-gray-600 mono text-sm focus:outline-none focus:border-cyan-500"
                  style={{ borderColor: 'var(--cyber-border)', width: '180px' }}
                  value={newPresetName}
                  onChange={(e) => setNewPresetName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSavePreset()}
                  autoFocus
                />
                <button
                  onClick={handleSavePreset}
                  disabled={!newPresetName.trim()}
                  className="p-2 rounded-lg border border-cyan-500 bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Check className="h-4 w-4" strokeWidth={1.5} />
                </button>
                <button
                  onClick={() => { setShowSavePresetDialog(false); setNewPresetName(''); }}
                  className="p-2 rounded-lg border border-gray-700 text-gray-400 hover:border-gray-600 transition-all"
                >
                  <X className="h-4 w-4" strokeWidth={1.5} />
                </button>
              </div>
            ) : (
              <button
                onClick={() => setShowSavePresetDialog(true)}
                className="inline-flex items-center px-4 py-2.5 rounded-lg border transition-all hover:border-amber-500"
                style={{
                  background: 'rgba(245, 158, 11, 0.1)',
                  borderColor: 'rgb(245, 158, 11)',
                  color: 'rgb(245, 158, 11)'
                }}
              >
                <Bookmark className="h-4 w-4 mr-2" strokeWidth={1.5} />
                <span className="mono text-sm font-medium">SAVE PRESET</span>
              </button>
            )}
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
          </div>
        )}
      </div>

      {/* Filter Presets - hidden in split mode */}
      {!isSplitMode && (
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
      )}

      {/* Search and Filters */}
      <div className={`rounded-lg border ${isSplitMode ? 'p-2' : 'p-4'}`} style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        <div className="flex flex-col md:flex-row gap-2">
          <div className="flex-1 relative">
            <Search className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${isSplitMode ? 'h-4 w-4' : 'h-5 w-5'} text-gray-500`} strokeWidth={1.5} />
            <input
              type="text"
              placeholder={isSplitMode ? "Search..." : "SEARCH CVE-ID OR DESCRIPTION..."}
              className={`w-full ${isSplitMode ? 'pl-9 pr-3 py-2 text-xs' : 'pl-12 pr-4 py-3 text-sm'} rounded-lg border bg-gray-900/50 text-gray-100 placeholder-gray-600 mono transition-all focus:outline-none focus:border-cyan-500`}
              style={{ borderColor: 'var(--cyber-border)' }}
              value={filters.text || ''}
              onChange={(e) => handleInputChange('text', e.target.value)}
            />
          </div>

          {/* Watchlist Dropdown - hidden in split mode */}
          {!isSplitMode && watchlists.length > 0 && (
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
                  {/* Watchlist Options - only show enabled watchlists */}
                  {watchlists.filter(wl => wl.enabled).map(wl => (
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

          {/* Filters button - hidden in split mode */}
          {!isSplitMode && (
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
          )}

          {/* Clear All Button - only shown when filters are active, not in split mode */}
          {hasActiveSearch && !isSplitMode && (
            <button
              onClick={() => {
                onFilterChange({
                  text: '',
                  cvss_min: 0,
                  cvss_max: 10,
                  kev: undefined,
                  published_from: undefined,
                  published_to: undefined,
                  published_relative: undefined,
                  modified_from: undefined,
                  modified_to: undefined,
                  modified_relative: undefined,
                  vendors: undefined,
                  products: undefined
                });
                setSelectedWatchlistId(null);
                onPageChange(0);
              }}
              className="flex items-center justify-center px-5 py-3 border rounded-lg mono text-sm font-medium transition-all border-red-500/50 text-red-400 hover:border-red-500 hover:bg-red-500/10"
              title="Clear all filters"
            >
              <X className="h-4 w-4 mr-2" strokeWidth={1.5} />
              CLEAR
            </button>
          )}
        </div>

        {/* Filter Panel - hidden in split mode */}
        {showFilters && !isSplitMode && (
          <div className="mt-4 space-y-4 p-4 rounded-lg border" style={{
            background: 'rgba(6, 182, 212, 0.03)',
            borderColor: 'var(--cyber-border)'
          }}>
            {/* Row 1: CVSS, EPSS, Exploit Maturity, KEV */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-2 mono">MIN CVSS SCORE</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  placeholder="0.0"
                  className="w-20 p-2.5 border rounded-lg bg-gray-900/50 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                  style={{ borderColor: 'var(--cyber-border)' }}
                  value={filters.cvss_min || ''}
                  onChange={(e) => handleInputChange('cvss_min', Math.min(10, Math.max(0, parseFloat(e.target.value) || 0)))}
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-2 mono">MIN EPSS %</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  step="1"
                  placeholder="0"
                  className="w-20 p-2.5 border rounded-lg bg-gray-900/50 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                  style={{ borderColor: 'var(--cyber-border)' }}
                  value={filters.epss_min ? Math.round(filters.epss_min * 100) : ''}
                  onChange={(e) => {
                    const pct = parseFloat(e.target.value) || 0;
                    handleInputChange('epss_min', Math.min(1, Math.max(0, pct / 100)));
                  }}
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-2 mono">EXPLOIT MATURITY</label>
                <select
                  className="w-full p-2.5 border rounded-lg bg-gray-900/50 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                  style={{ borderColor: 'var(--cyber-border)' }}
                  value={filters.exploit_maturity || ''}
                  onChange={(e) => handleInputChange('exploit_maturity', e.target.value || undefined)}
                >
                  <option value="">Any</option>
                  <option value="A">Attacked</option>
                  <option value="H">High</option>
                  <option value="F">Functional</option>
                  <option value="POC">Proof-of-Concept</option>
                  <option value="U">Unproven</option>
                </select>
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

            {/* Row 2: Date Ranges (Published & Modified side by side) */}
            <div className="pt-3 border-t" style={{ borderColor: 'var(--cyber-border)' }}>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Published Date */}
                <div>
                  <label className="block text-xs font-semibold text-gray-400 mb-2 mono">PUBLISHED</label>
                  <div className="flex flex-wrap items-center gap-2">
                    {[
                      { label: 'Today', days: 0, relative: 'today' },
                      { label: 'Last 7 Days', days: 7, relative: 'last_7_days' },
                      { label: 'Last 30 Days', days: 30, relative: 'last_30_days' },
                    ].map(preset => {
                      const getPresetDates = () => {
                        const today = new Date().toISOString().split('T')[0];
                        if (preset.days === 0) {
                          return { from: today, to: undefined };
                        }
                        const to = new Date();
                        const from = new Date(to);
                        from.setDate(from.getDate() - preset.days);
                        return {
                          from: from.toISOString().split('T')[0],
                          to: to.toISOString().split('T')[0]
                        };
                      };
                      const isActive = () => {
                        // Check if using this relative preset
                        if (filters.published_relative === preset.relative) return true;
                        // Fallback to checking absolute dates
                        const { from, to } = getPresetDates();
                        if (preset.days === 0) {
                          return filters.published_from === from && !filters.published_to && !filters.published_relative;
                        }
                        return filters.published_from === from && filters.published_to === to && !filters.published_relative;
                      };
                      return (
                        <button
                          key={`pub-${preset.label}`}
                          onClick={() => {
                            const { from, to } = getPresetDates();
                            // Store both computed dates AND relative preset type
                            onFilterChange({
                              ...filters,
                              published_from: from,
                              published_to: to,
                              published_relative: preset.relative
                            });
                            onPageChange(0);
                          }}
                          className={`px-2 py-1 rounded border mono text-xs transition-all ${
                            isActive() ? 'border-cyan-500 bg-cyan-500/20 text-cyan-400' : 'border-gray-700 text-gray-400 hover:border-gray-600'
                          }`}
                        >
                          {preset.label}
                        </button>
                      );
                    })}
                    <input
                      type="date"
                      className="p-1 border rounded bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500 w-28"
                      style={{ borderColor: 'var(--cyber-border)' }}
                      value={filters.published_from || ''}
                      onChange={(e) => handleInputChange('published_from', e.target.value || undefined)}
                    />
                    <span className="text-gray-500 mono text-xs">-</span>
                    <input
                      type="date"
                      className="p-1 border rounded bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500 w-28"
                      style={{ borderColor: 'var(--cyber-border)' }}
                      value={filters.published_to || ''}
                      onChange={(e) => handleInputChange('published_to', e.target.value || undefined)}
                    />
                    {(filters.published_from || filters.published_to) && (
                      <button
                        onClick={() => { onFilterChange({ ...filters, published_from: undefined, published_to: undefined, published_relative: undefined }); onPageChange(0); }}
                        className="p-1 rounded border border-gray-700 text-gray-500 hover:text-gray-300"
                      >
                        <X className="h-3 w-3" strokeWidth={1.5} />
                      </button>
                    )}
                  </div>
                </div>

                {/* Modified Date */}
                <div>
                  <label className="block text-xs font-semibold text-gray-400 mb-2 mono">MODIFIED</label>
                  <div className="flex flex-wrap items-center gap-2">
                    {[
                      { label: 'Today', days: 0, relative: 'today' },
                      { label: 'Last 7 Days', days: 7, relative: 'last_7_days' },
                      { label: 'Last 30 Days', days: 30, relative: 'last_30_days' },
                    ].map(preset => {
                      const getPresetDates = () => {
                        const today = new Date().toISOString().split('T')[0];
                        if (preset.days === 0) {
                          return { from: today, to: undefined };
                        }
                        const to = new Date();
                        const from = new Date(to);
                        from.setDate(from.getDate() - preset.days);
                        return {
                          from: from.toISOString().split('T')[0],
                          to: to.toISOString().split('T')[0]
                        };
                      };
                      const isActive = () => {
                        // Check if using this relative preset
                        if (filters.modified_relative === preset.relative) return true;
                        // Fallback to checking absolute dates
                        const { from, to } = getPresetDates();
                        if (preset.days === 0) {
                          return filters.modified_from === from && !filters.modified_to && !filters.modified_relative;
                        }
                        return filters.modified_from === from && filters.modified_to === to && !filters.modified_relative;
                      };
                      return (
                        <button
                          key={`mod-${preset.label}`}
                          onClick={() => {
                            const { from, to } = getPresetDates();
                            // Store both computed dates AND relative preset type
                            onFilterChange({
                              ...filters,
                              modified_from: from,
                              modified_to: to,
                              modified_relative: preset.relative
                            });
                            onPageChange(0);
                          }}
                          className={`px-2 py-1 rounded border mono text-xs transition-all ${
                            isActive() ? 'border-cyan-500 bg-cyan-500/20 text-cyan-400' : 'border-gray-700 text-gray-400 hover:border-gray-600'
                          }`}
                        >
                          {preset.label}
                        </button>
                      );
                    })}
                    <input
                      type="date"
                      className="p-1 border rounded bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500 w-28"
                      style={{ borderColor: 'var(--cyber-border)' }}
                      value={filters.modified_from || ''}
                      onChange={(e) => handleInputChange('modified_from', e.target.value || undefined)}
                    />
                    <span className="text-gray-500 mono text-xs">-</span>
                    <input
                      type="date"
                      className="p-1 border rounded bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500 w-28"
                      style={{ borderColor: 'var(--cyber-border)' }}
                      value={filters.modified_to || ''}
                      onChange={(e) => handleInputChange('modified_to', e.target.value || undefined)}
                    />
                    {(filters.modified_from || filters.modified_to) && (
                      <button
                        onClick={() => { onFilterChange({ ...filters, modified_from: undefined, modified_to: undefined, modified_relative: undefined }); onPageChange(0); }}
                        className="p-1 rounded border border-gray-700 text-gray-500 hover:text-gray-300"
                      >
                        <X className="h-3 w-3" strokeWidth={1.5} />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Row 4: Vendor/Product Filter */}
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

      </div>

      {/* CVE Table with Virtual Scrolling */}
      <div className={`rounded-lg border overflow-hidden flex flex-col ${isSplitMode ? 'flex-1' : ''}`} style={{
        background: isSplitMode ? 'transparent' : 'var(--cyber-surface)',
        borderColor: isSplitMode ? 'transparent' : 'var(--cyber-border)',
        height: isSplitMode ? undefined : 'calc(100vh - 340px)',
        minHeight: isSplitMode ? undefined : '400px'
      }}>
        {/* Top Pagination - shown when there are multiple pages, not in split mode */}
        {!isSplitMode && totalPages > 1 && cves.length > 0 && hasActiveSearch && (
          <PaginationControls position="top" />
        )}

        {/* Header Row - Fixed */}
        <div
          className="grid bg-gray-900/30 flex-shrink-0"
          style={{
            gridTemplateColumns: isSplitMode ? '1fr 80px' : '180px 140px 1fr 120px',
            borderBottom: '1px solid var(--cyber-border)'
          }}
        >
          <SortableHeader label="CVE ID" column="id" />
          <SortableHeader label={isSplitMode ? "CVSS" : "SEVERITY"} column="score" />
          {!isSplitMode && (
            <>
              <div className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono">
                DESCRIPTION
              </div>
              <SortableHeader label="PUBLISHED" column="published" />
            </>
          )}
        </div>

        {/* Body - Flex grow to fill remaining space */}
        <div className="flex-1 overflow-hidden">
          {!hasActiveSearch ? (
            <div className="px-6 py-20 text-center h-full flex items-center justify-center">
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
              className="h-full overflow-auto"
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
                const isHighlighted = highlightedCveId === cve.id;
                const isSelected = selectedCveId === cve.id;
                return (
                  <div
                    key={cve.id}
                    data-index={virtualRow.index}
                    ref={rowVirtualizer.measureElement}
                    className={`grid group cursor-pointer transition-all hover:bg-cyan-500/5 ${
                      isHighlighted ? 'animate-highlight-fade' : ''
                    } ${isSplitMode && isSelected ? 'bg-cyan-500/10' : ''}`}
                    style={{
                      gridTemplateColumns: isSplitMode ? '1fr 80px' : '180px 140px 1fr 120px',
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      transform: `translateY(${virtualRow.start}px)`,
                      borderBottom: !isLast ? '1px solid var(--cyber-border)' : 'none',
                      ...(isHighlighted ? {
                        background: 'rgba(6, 182, 212, 0.15)',
                        boxShadow: 'inset 0 0 0 1px rgba(6, 182, 212, 0.5)'
                      } : {}),
                      ...(isSplitMode && isSelected && !isHighlighted ? {
                        borderLeft: '3px solid var(--cyber-accent)'
                      } : {})
                    }}
                    onClick={() => onSelectCve(cve.id, parentRef.current?.scrollTop)}
                  >
                    <div className={`${isSplitMode ? 'px-3 py-2' : 'px-6 py-4'} whitespace-nowrap`}>
                      <div className="flex items-center space-x-2">
                        <span className={`${isSplitMode ? 'text-xs' : 'text-sm'} font-bold text-cyan-400 mono group-hover:text-cyan-300 transition-colors`}>
                          {cve.id}
                        </span>
                        {cve.kev && (
                          <span className={`inline-flex items-center ${isSplitMode ? 'px-1 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs'} rounded font-bold bg-red-500/20 text-red-400 border border-red-500/30 mono`}>
                            KEV
                          </span>
                        )}
                      </div>
                    </div>
                    <div className={`${isSplitMode ? 'px-2 py-2' : 'px-6 py-4'} whitespace-nowrap`}>
                      {isSplitMode ? (
                        <span className={`text-xs font-bold mono ${
                          cve.cvssSeverity === 'CRITICAL' ? 'text-red-400' :
                          cve.cvssSeverity === 'HIGH' ? 'text-orange-400' :
                          cve.cvssSeverity === 'MEDIUM' ? 'text-yellow-400' :
                          cve.cvssSeverity === 'LOW' ? 'text-green-400' : 'text-gray-400'
                        }`}>
                          {cve.cvssScore?.toFixed(1) || 'N/A'}
                        </span>
                      ) : (
                        getSeverityBadge(cve.cvssSeverity, cve.cvssScore)
                      )}
                    </div>
                    {!isSplitMode && (
                      <>
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
                      </>
                    )}
                  </div>
                );
              })}
            </div>
            </div>
          ) : (
            <div className="px-6 py-16 text-center h-full flex items-center justify-center">
              <div className="flex flex-col items-center space-y-4">
                <div className="w-12 h-12 rounded-lg border border-gray-700 flex items-center justify-center">
                  <Search className="h-6 w-6 text-gray-600" strokeWidth={1.5} />
                </div>
                <p className="text-gray-500 mono text-sm">NO RESULTS MATCH YOUR SEARCH</p>
                <button
                  onClick={() => {
                    onFilterChange({
                      text: '',
                      cvss_min: 0,
                      cvss_max: 10,
                      kev: undefined,
                      published_from: undefined,
                      published_to: undefined,
                      published_relative: undefined,
                      modified_from: undefined,
                      modified_to: undefined,
                      modified_relative: undefined,
                      vendors: undefined,
                      products: undefined
                    });
                    setSelectedWatchlistId(null);
                    onPageChange(0);
                  }}
                  className="flex items-center px-4 py-2 border rounded-lg mono text-sm font-medium transition-all border-red-500/50 text-red-400 hover:border-red-500 hover:bg-red-500/10"
                >
                  <X className="h-4 w-4 mr-2" strokeWidth={1.5} />
                  CLEAR FILTERS
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Bottom Pagination - scrolls to top when used, hidden in split mode */}
        {!isSplitMode && totalPages > 1 && cves.length > 0 && hasActiveSearch && (
          <PaginationControls position="bottom" />
        )}
      </div>
    </div>
  );
};

export default CveList;
