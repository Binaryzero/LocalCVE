import React, { useState, useEffect, useCallback } from 'react';
import Layout from './components/Layout';
import CveList from './components/CveList';
import Watchlists from './components/Watchlists';
import Jobs from './components/Jobs';
import Alerts from './components/Alerts';
import CveDetail from './components/CveDetail';
import Settings from './components/Settings';
import { Cve, JobRun, Watchlist, Alert, QueryModel, AppSettings } from './types';

const SETTINGS_KEY = 'localcve_settings';
const LAYOUT_MODE_KEY = 'localcve_layout_mode';
const DEFAULT_SETTINGS: AppSettings = {
  hideRejectedCves: true,
  hideDisputedCves: false
};

type LayoutMode = 'list' | 'split';

const App: React.FC = () => {
  const [activePage, setActivePage] = useState('cves');
  const [cves, setCves] = useState<Cve[]>([]);
  const [totalCves, setTotalCves] = useState(0);
  const [jobs, setJobs] = useState<JobRun[]>([]);
  const [watchlists, setWatchlists] = useState<Watchlist[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<QueryModel>({ text: '', cvss_min: 0, cvss_max: 10 });
  const [page, setPage] = useState(0);
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<string>('published');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const pageSize = 50;

  // Sticky list position state
  const [listScrollPosition, setListScrollPosition] = useState(0);
  const [lastViewedCveId, setLastViewedCveId] = useState<string | null>(null);

  // Layout mode state with localStorage persistence
  const [layoutMode, setLayoutMode] = useState<LayoutMode>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem(LAYOUT_MODE_KEY);
      if (saved === 'list' || saved === 'split') return saved;
    }
    return 'list';
  });

  // Persist layout mode to localStorage
  useEffect(() => {
    localStorage.setItem(LAYOUT_MODE_KEY, layoutMode);
  }, [layoutMode]);

  const toggleLayoutMode = useCallback(() => {
    setLayoutMode(prev => prev === 'list' ? 'split' : 'list');
  }, []);

  // Settings state with localStorage persistence
  const [settings, setSettings] = useState<AppSettings>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem(SETTINGS_KEY);
      if (saved) {
        try {
          return { ...DEFAULT_SETTINGS, ...JSON.parse(saved) };
        } catch {
          return DEFAULT_SETTINGS;
        }
      }
    }
    return DEFAULT_SETTINGS;
  });

  // Persist settings to localStorage
  useEffect(() => {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  }, [settings]);

  // Navigate to a page, clearing CVE detail view unless explicitly viewing a CVE
  const handleNavigate = (page: string) => {
    setSelectedCveId(null); // Clear any open CVE detail when switching pages
    setActivePage(page);
  };

  const viewCve = (id: string) => {
    setSelectedCveId(id);
    setActivePage('cves');
  };

  // Separate job fetching for higher frequency/responsiveness
  const fetchJobs = useCallback(async () => {
    try {
      // Add timestamp to prevent caching
      const res = await fetch(`/api/jobs?t=${Date.now()}`);
      if (res.ok) {
        setJobs(await res.json());
      }
    } catch (error) {
      console.error('Error fetching jobs:', error);
    }
  }, []);

  // Handler for column sort changes
  const handleSortChange = (column: string, order: 'asc' | 'desc') => {
    setSortBy(column);
    setSortOrder(order);
    setPage(0); // Reset to first page on sort change
  };

  const fetchData = useCallback(async () => {
    try {
      const q = new URLSearchParams();
      if (filters.text) q.set('search', filters.text);
      // Use explicit null/undefined check - 0 is a valid CVSS score
      if (filters.cvss_min !== undefined && filters.cvss_min !== null) {
        q.set('cvss_min', filters.cvss_min.toString());
      }
      // Date filters - prefer relative dates (truly dynamic) over absolute
      if (filters.published_relative) {
        q.set('published_relative', filters.published_relative);
      } else {
        if (filters.published_from) q.set('published_from', filters.published_from);
        if (filters.published_to) q.set('published_to', filters.published_to);
      }
      if (filters.modified_relative) {
        q.set('modified_relative', filters.modified_relative);
      } else {
        if (filters.modified_from) q.set('modified_from', filters.modified_from);
        if (filters.modified_to) q.set('modified_to', filters.modified_to);
      }
      // Vendor/product filters
      if (filters.vendors && filters.vendors.length > 0) q.set('vendors', filters.vendors.join(','));
      if (filters.products && filters.products.length > 0) q.set('products', filters.products.join(','));
      // KEV filter
      if (filters.kev) q.set('kev', 'true');
      // EPSS filter
      if (filters.epss_min !== undefined && filters.epss_min !== null) {
        q.set('epss_min', filters.epss_min.toString());
      }
      // Exploit maturity filter
      if (filters.exploit_maturity) q.set('exploit_maturity', filters.exploit_maturity);
      // Settings filters (hide rejected/disputed)
      if (settings.hideRejectedCves) q.set('hide_rejected', 'true');
      if (settings.hideDisputedCves) q.set('hide_disputed', 'true');
      // Sort parameters
      if (sortBy) q.set('sort_by', sortBy);
      if (sortOrder) q.set('sort_order', sortOrder);
      q.set('limit', pageSize.toString());
      q.set('offset', (page * pageSize).toString());

      const results = await Promise.allSettled([
        fetch(`/api/cves?${q.toString()}`),
        fetch('/api/watchlists'),
        fetch('/api/alerts')
      ]);

      const [cvesRes, wlRes, alertsRes] = results;

      if (cvesRes.status === 'fulfilled' && cvesRes.value.ok) {
        const data = await cvesRes.value.json();
        setCves(data.cves || []);
        setTotalCves(data.totalCount || 0);
      }

      if (wlRes.status === 'fulfilled' && wlRes.value.ok) {
        setWatchlists(await wlRes.value.json());
      }

      if (alertsRes.status === 'fulfilled' && alertsRes.value.ok) {
        setAlerts(await alertsRes.value.json());
      }

      // Fetch jobs separately
      await fetchJobs();

    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  }, [fetchJobs, filters, page, sortBy, sortOrder, settings]);

  // Initial load
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Poll for job updates frequently (3s), full data less frequently if needed, 
  // but for now we poll everything to keep dashboard alive.
  useEffect(() => {
    const interval = setInterval(() => {
      fetchData();
    }, 5000); // 5 seconds general poll
    return () => clearInterval(interval);
  }, [fetchData]);

  // Special poll for jobs if one is running
  useEffect(() => {
    const interval = setInterval(() => {
      fetchJobs();
    }, 3000);
    return () => clearInterval(interval);
  }, [fetchJobs]);

  // --- Watchlist Logic ---
  const handleSaveWatchlist = async (query: QueryModel) => {
    try {
      const response = await fetch('/api/watchlists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `Watchlist ${watchlists.length + 1}`,
          query,
          enabled: true
        }),
      });
      if (response.ok) {
        fetchData(); // Refresh list
        setActivePage('watchlists');
      }
    } catch (err) {
      console.error("Failed to save watchlist", err);
    }
  };

  const handleToggleWatchlist = async (id: string) => {
    const watchlist = watchlists.find(w => w.id === id);
    if (!watchlist) return;

    try {
      await fetch(`/api/watchlists/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...watchlist, enabled: !watchlist.enabled })
      });
      fetchData();
    } catch (err) {
      console.error("Failed to toggle watchlist", err);
    }
  };

  const handleDeleteWatchlist = async (id: string) => {
    try {
      await fetch(`/api/watchlists/${id}`, { method: 'DELETE' });
      setWatchlists(prev => prev.filter(w => w.id !== id));
    } catch (err) {
      console.error("Failed to delete watchlist", err);
    }
  };

  const handleUpdateWatchlist = async (id: string, updates: { name?: string; query?: QueryModel }) => {
    const watchlist = watchlists.find(w => w.id === id);
    if (!watchlist) return;

    try {
      const updated = {
        ...watchlist,
        ...(updates.name !== undefined && { name: updates.name }),
        ...(updates.query !== undefined && { query: updates.query })
      };
      await fetch(`/api/watchlists/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated)
      });
      // Optimistic update for watchlists
      setWatchlists(prev => prev.map(w => w.id === id ? { ...w, ...updates } : w));
      // Also update alert names if watchlist was renamed
      if (updates.name !== undefined) {
        setAlerts(prev => prev.map(a =>
          a.watchlistId === id ? { ...a, watchlistName: updates.name! } : a
        ));
      }
    } catch (err) {
      console.error("Failed to update watchlist", err);
      fetchData(); // Refetch on error to restore correct state
    }
  };

  // --- Alert Logic ---
  const handleMarkAlertRead = async (id: string) => {
    try {
      await fetch(`/api/alerts/${id}/read`, { method: 'PUT' });
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, read: true } : a));
    } catch (err) {
      console.error("Failed to mark alert read", err);
    }
  };

  const handleDeleteAlert = async (id: string) => {
    try {
      await fetch(`/api/alerts/${id}`, { method: 'DELETE' });
      setAlerts(prev => prev.filter(a => a.id !== id));
    } catch (err) {
      console.error("Failed to delete alert", err);
    }
  };

  const handleMarkAllAlertsRead = async () => {
    try {
      await fetch('/api/alerts/mark-all-read', { method: 'PUT' });
      setAlerts(prev => prev.map(a => ({ ...a, read: true })));
    } catch (err) {
      console.error("Failed to mark all alerts read", err);
    }
  };

  const handleMarkAllAlertsUnread = async () => {
    try {
      await fetch('/api/alerts/mark-all-unread', { method: 'PUT' });
      setAlerts(prev => prev.map(a => ({ ...a, read: false })));
    } catch (err) {
      console.error("Failed to mark all alerts unread", err);
    }
  };

  const handleMarkAlertUnread = async (id: string) => {
    try {
      await fetch(`/api/alerts/${id}/unread`, { method: 'PUT' });
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, read: false } : a));
    } catch (err) {
      console.error("Failed to mark alert unread", err);
    }
  };

  const handleDeleteAllAlerts = async () => {
    try {
      await fetch('/api/alerts/delete-all', { method: 'DELETE' });
      setAlerts([]);
    } catch (err) {
      console.error("Failed to delete all alerts", err);
    }
  };

  // --- Ingestion Logic ---
  const handleRunIngest = async (useBulkMode = false) => {
    const endpoint = useBulkMode ? '/api/ingest/bulk' : '/api/ingest';
    try {
      const response = await fetch(endpoint, { method: 'POST' });
      if (response.ok) {
        const data = await response.json();
        // Optimistically add the new job to state so UI updates instantly
        if (data.jobId) {
          const newJob: JobRun = {
            id: data.jobId,
            startTime: new Date().toISOString(),
            endTime: null,
            status: 'RUNNING',
            itemsProcessed: 0,
            progressPercent: 0,
            itemsAdded: 0,
            itemsUpdated: 0,
            itemsUnchanged: 0,
            currentPhase: useBulkMode ? 'Starting (Bulk Mode)' : 'Starting',
            lastHeartbeat: new Date().toISOString(),
            totalFiles: null,
            error: null
          };
          setJobs(prev => [newJob, ...prev]);
        }
        // Trigger a real fetch shortly after to sync
        setTimeout(fetchJobs, 500);
      } else {
        console.error("Ingestion start failed", await response.text());
      }
    } catch (err) {
      console.error("Failed to start ingestion", err);
    }
  };

  const handleRunBulkIngest = () => handleRunIngest(true);

  const handleRunCvssBtSync = async () => {
    try {
      const response = await fetch('/api/ingest/cvss-bt', { method: 'POST' });
      if (response.ok) {
        const data = await response.json();
        console.log('CVSS-BT sync complete:', data);
        // Refresh CVE data after enrichment
        fetchData();
      } else {
        console.error('CVSS-BT sync failed:', await response.text());
      }
    } catch (err) {
      console.error('Failed to run CVSS-BT sync:', err);
    }
  };

  const handleRunTrickestSync = async () => {
    try {
      const response = await fetch('/api/ingest/trickest', { method: 'POST' });
      if (response.ok) {
        const data = await response.json();
        console.log('Trickest sync complete:', data);
        // Refresh CVE data after enrichment
        fetchData();
      } else {
        console.error('Trickest sync failed:', await response.text());
      }
    } catch (err) {
      console.error('Failed to run Trickest sync:', err);
    }
  };

  // CVE navigation handlers for prev/next in detail view
  const cveIds = cves.map(c => c.id);
  const currentCveIndex = selectedCveId ? cveIds.indexOf(selectedCveId) : -1;

  const handleNavigatePrev = useCallback(() => {
    if (currentCveIndex > 0) {
      setSelectedCveId(cveIds[currentCveIndex - 1]);
    }
  }, [currentCveIndex, cveIds]);

  const handleNavigateNext = useCallback(() => {
    if (currentCveIndex < cveIds.length - 1) {
      setSelectedCveId(cveIds[currentCveIndex + 1]);
    }
  }, [currentCveIndex, cveIds]);

  // Handler for selecting a CVE - saves position for sticky nav
  const handleSelectCve = useCallback((cveId: string, scrollPosition?: number) => {
    if (scrollPosition !== undefined) {
      setListScrollPosition(scrollPosition);
    }
    setLastViewedCveId(cveId);
    setSelectedCveId(cveId);
  }, []);

  const renderContent = () => {
    if (loading && cves.length === 0 && jobs.length === 0) {
      return <div className="p-8 text-center text-gray-500">Loading data...</div>;
    }

    switch (activePage) {
      case 'cves':
        // Split pane mode: show list and detail side by side
        if (layoutMode === 'split') {
          return (
            <div className="grid gap-4 h-full" style={{ gridTemplateColumns: '420px 1fr' }}>
              <div className="overflow-hidden rounded-lg border" style={{
                background: 'var(--cyber-surface)',
                borderColor: 'var(--cyber-border)',
                height: 'calc(100vh - 100px)'
              }}>
                <CveList
                  cves={cves}
                  onSaveWatchlist={handleSaveWatchlist}
                  filters={filters}
                  onFilterChange={setFilters}
                  page={page}
                  onPageChange={setPage}
                  totalCount={totalCves}
                  pageSize={pageSize}
                  onSelectCve={handleSelectCve}
                  watchlists={watchlists}
                  sortBy={sortBy}
                  sortOrder={sortOrder}
                  onSortChange={handleSortChange}
                  initialScrollPosition={listScrollPosition}
                  lastViewedCveId={lastViewedCveId}
                  layoutMode="split"
                  onToggleLayout={toggleLayoutMode}
                  selectedCveId={selectedCveId}
                />
              </div>
              <div className="overflow-auto rounded-lg border" style={{
                background: 'var(--cyber-surface)',
                borderColor: 'var(--cyber-border)',
                height: 'calc(100vh - 100px)'
              }}>
                {selectedCveId ? (
                  <CveDetail
                    id={selectedCveId}
                    onBack={() => setSelectedCveId(null)}
                    onApplyFilter={(filter) => { setFilters({ ...filters, ...filter }); setSelectedCveId(null); setPage(0); }}
                    onNavigatePrev={currentCveIndex > 0 ? handleNavigatePrev : undefined}
                    onNavigateNext={currentCveIndex < cveIds.length - 1 ? handleNavigateNext : undefined}
                    currentIndex={currentCveIndex}
                    totalCount={cveIds.length}
                    showBackButton={false}
                  />
                ) : (
                  <div className="h-full flex items-center justify-center">
                    <div className="text-center">
                      <div className="w-16 h-16 mx-auto rounded-lg border border-gray-700 flex items-center justify-center mb-4">
                        <svg className="h-8 w-8 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                          <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                      </div>
                      <p className="text-gray-500 mono text-sm">SELECT A CVE TO VIEW DETAILS</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        }
        // Standard list mode: show list or detail
        if (selectedCveId) return (
          <CveDetail
            id={selectedCveId}
            onBack={() => setSelectedCveId(null)}
            onApplyFilter={(filter) => { setFilters({ ...filters, ...filter }); setSelectedCveId(null); setPage(0); }}
            onNavigatePrev={currentCveIndex > 0 ? handleNavigatePrev : undefined}
            onNavigateNext={currentCveIndex < cveIds.length - 1 ? handleNavigateNext : undefined}
            currentIndex={currentCveIndex}
            totalCount={cveIds.length}
          />
        );
        return (
          <CveList
            cves={cves}
            onSaveWatchlist={handleSaveWatchlist}
            filters={filters}
            onFilterChange={setFilters}
            page={page}
            onPageChange={setPage}
            totalCount={totalCves}
            pageSize={pageSize}
            onSelectCve={handleSelectCve}
            watchlists={watchlists}
            sortBy={sortBy}
            sortOrder={sortOrder}
            onSortChange={handleSortChange}
            initialScrollPosition={listScrollPosition}
            lastViewedCveId={lastViewedCveId}
            layoutMode="list"
            onToggleLayout={toggleLayoutMode}
          />
        );
      case 'watchlists':
        return <Watchlists watchlists={watchlists} onToggle={handleToggleWatchlist} onDelete={handleDeleteWatchlist} onUpdate={handleUpdateWatchlist} onNavigate={handleNavigate} onApplyFilter={(filter) => { setFilters(filter); setPage(0); }} />;
      case 'jobs':
        return <Jobs jobs={jobs} onRunIngest={() => handleRunIngest(false)} onRunBulkIngest={handleRunBulkIngest} onRunCvssBtSync={handleRunCvssBtSync} onRunTrickestSync={handleRunTrickestSync} />;
      case 'alerts':
        return <Alerts alerts={alerts} onMarkRead={handleMarkAlertRead} onMarkUnread={handleMarkAlertUnread} onDelete={handleDeleteAlert} onMarkAllRead={handleMarkAllAlertsRead} onMarkAllUnread={handleMarkAllAlertsUnread} onDeleteAll={handleDeleteAllAlerts} onViewCve={viewCve} />;
      case 'settings':
        return <Settings settings={settings} onSettingsChange={setSettings} />;
      default:
        if (selectedCveId) return (
          <CveDetail
            id={selectedCveId}
            onBack={() => setSelectedCveId(null)}
            onApplyFilter={(filter) => { setFilters({ ...filters, ...filter }); setSelectedCveId(null); setPage(0); }}
            onNavigatePrev={currentCveIndex > 0 ? handleNavigatePrev : undefined}
            onNavigateNext={currentCveIndex < cveIds.length - 1 ? handleNavigateNext : undefined}
            currentIndex={currentCveIndex}
            totalCount={cveIds.length}
          />
        );
        return (
          <CveList
            cves={cves}
            onSaveWatchlist={handleSaveWatchlist}
            filters={filters}
            onFilterChange={setFilters}
            page={page}
            onPageChange={setPage}
            totalCount={totalCves}
            pageSize={pageSize}
            onSelectCve={handleSelectCve}
            watchlists={watchlists}
            sortBy={sortBy}
            sortOrder={sortOrder}
            onSortChange={handleSortChange}
            initialScrollPosition={listScrollPosition}
            lastViewedCveId={lastViewedCveId}
          />
        );
    }
  };

  return (
    <Layout activePage={activePage} onNavigate={handleNavigate} unreadAlertCount={alerts.filter(a => !a.read).length}>
      {renderContent()}
    </Layout>
  );
};

export default App;