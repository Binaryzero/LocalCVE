import React, { useState, useEffect, useCallback } from 'react';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import CveList from './components/CveList';
import Watchlists from './components/Watchlists';
import Jobs from './components/Jobs';
import Alerts from './components/Alerts';
import CveDetail from './components/CveDetail';
import { Cve, JobRun, Watchlist, Alert, QueryModel } from './types';

const App: React.FC = () => {
  const [activePage, setActivePage] = useState('dashboard');
  const [cves, setCves] = useState<Cve[]>([]);
  const [totalCves, setTotalCves] = useState(0);
  const [jobs, setJobs] = useState<JobRun[]>([]);
  const [watchlists, setWatchlists] = useState<Watchlist[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<QueryModel>({ text: '', cvss_min: 0, cvss_max: 10 });
  const [page, setPage] = useState(0);
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const pageSize = 50;

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

  const fetchData = useCallback(async () => {
    try {
      const q = new URLSearchParams();
      if (filters.text) q.set('search', filters.text);
      if (filters.cvss_min) q.set('cvss_min', filters.cvss_min.toString());
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
  }, [fetchJobs, filters, page]);

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

  // --- Ingestion Logic ---
  const handleRunIngest = async () => {
    try {
      const response = await fetch('/api/ingest', { method: 'POST' });
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

  const renderContent = () => {
    if (loading && cves.length === 0 && jobs.length === 0) {
      return <div className="p-8 text-center text-gray-500">Loading data...</div>;
    }

    switch (activePage) {
      case 'dashboard':
        return <Dashboard cves={cves} alerts={alerts} onNavigate={setActivePage} onViewCve={viewCve} />;
      case 'cves':
        if (selectedCveId) return <CveDetail id={selectedCveId} onBack={() => setSelectedCveId(null)} />;
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
            onSelectCve={setSelectedCveId}
          />
        );
      case 'watchlists':
        return <Watchlists watchlists={watchlists} onToggle={handleToggleWatchlist} onDelete={handleDeleteWatchlist} onNavigate={setActivePage} />;
      case 'jobs':
        return <Jobs jobs={jobs} onRunIngest={handleRunIngest} />;
      case 'alerts':
        return <Alerts alerts={alerts} onMarkRead={handleMarkAlertRead} onDelete={handleDeleteAlert} onViewCve={viewCve} />;
      default:
        return <Dashboard cves={cves} alerts={alerts} onNavigate={setActivePage} onViewCve={viewCve} />;
    }
  };

  return (
    <Layout activePage={activePage} onNavigate={setActivePage}>
      {renderContent()}
    </Layout>
  );
};

export default App;