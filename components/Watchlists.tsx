import React from 'react';
import { Eye, Trash2, Plus, ToggleLeft, ToggleRight, Target } from 'lucide-react';
import { Watchlist } from '../types';

interface WatchlistsProps {
  watchlists: Watchlist[];
  onToggle: (id: string) => void;
  onDelete: (id: string) => void;
  onNavigate: (page: string) => void;
}

const Watchlists: React.FC<WatchlistsProps> = ({ watchlists, onToggle, onDelete, onNavigate }) => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-100 mono tracking-tight">WATCHLISTS</h1>
          <p className="text-sm text-gray-500 mono mt-1">Automated threat monitoring</p>
        </div>
        <button
          onClick={() => onNavigate('cves')}
          className="inline-flex items-center px-5 py-3 rounded-lg border transition-all hover:border-cyan-500"
          style={{
            background: 'rgba(6, 182, 212, 0.1)',
            borderColor: 'var(--cyber-accent)',
            color: 'var(--cyber-accent)'
          }}
        >
          <Plus className="h-4 w-4 mr-2" strokeWidth={1.5} />
          <span className="mono text-sm font-medium">NEW WATCHLIST</span>
        </button>
      </div>

      {/* Watchlist Grid */}
      {watchlists.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {watchlists.map((wl) => (
            <div
              key={wl.id}
              className="group rounded-lg border overflow-hidden transition-all hover:border-cyan-500/50"
              style={{
                background: 'var(--cyber-surface)',
                borderColor: 'var(--cyber-border)'
              }}
            >
              <div className="p-6 space-y-4">
                {/* Header */}
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <div
                      className={`p-2.5 rounded-lg transition-all ${
                        wl.enabled
                          ? 'bg-cyan-500/20 border border-cyan-500/30'
                          : 'bg-gray-800 border border-gray-700'
                      }`}
                    >
                      <Eye
                        className={`h-5 w-5 ${wl.enabled ? 'text-cyan-400' : 'text-gray-600'}`}
                        strokeWidth={1.5}
                      />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-gray-100 mono">{wl.name}</h3>
                      <p className="text-xs text-gray-500 mono mt-0.5">
                        {wl.enabled ? 'ACTIVE' : 'DISABLED'}
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={() => onToggle(wl.id)}
                    className="transition-transform hover:scale-110"
                  >
                    {wl.enabled ? (
                      <ToggleRight className="h-9 w-9 text-cyan-400" strokeWidth={1.5} />
                    ) : (
                      <ToggleLeft className="h-9 w-9 text-gray-600" strokeWidth={1.5} />
                    )}
                  </button>
                </div>

                {/* Query */}
                <div>
                  <label className="text-xs font-semibold text-gray-500 mono uppercase mb-2 block">
                    Query
                  </label>
                  <div
                    className="p-3 rounded-lg border text-xs overflow-x-auto max-h-24"
                    style={{
                      background: 'rgba(6, 182, 212, 0.03)',
                      borderColor: 'var(--cyber-border)'
                    }}
                  >
                    <pre className="text-gray-400 mono">{JSON.stringify(wl.query, null, 2)}</pre>
                  </div>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 gap-3 pt-3 border-t" style={{ borderColor: 'var(--cyber-border)' }}>
                  <div>
                    <p className="text-xs text-gray-500 mono mb-1">MATCHES</p>
                    <p className="text-xl font-bold text-cyan-400 mono">{wl.matchCount || 0}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-500 mono mb-1">LAST RUN</p>
                    <p className="text-sm text-gray-400 mono">
                      {wl.lastRun ? new Date(wl.lastRun).toLocaleDateString('en-US', {
                        month: '2-digit',
                        day: '2-digit'
                      }) : 'Never'}
                    </p>
                  </div>
                </div>

                {/* Actions */}
                <button
                  onClick={() => onDelete(wl.id)}
                  className="w-full flex items-center justify-center px-4 py-2.5 border rounded-lg transition-all hover:border-red-500/50 hover:bg-red-500/10 text-gray-400 hover:text-red-400 mono text-sm font-medium"
                  style={{ borderColor: 'var(--cyber-border)' }}
                >
                  <Trash2 className="h-4 w-4 mr-2" strokeWidth={1.5} />
                  DELETE
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="rounded-lg border p-16 text-center" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)',
          borderStyle: 'dashed'
        }}>
          <div className="w-20 h-20 mx-auto rounded-lg border-2 border-gray-700 flex items-center justify-center mb-6">
            <Target className="h-10 w-10 text-gray-600" strokeWidth={1.5} />
          </div>
          <h3 className="text-lg font-semibold text-gray-100 mono mb-2">NO WATCHLISTS CONFIGURED</h3>
          <p className="text-sm text-gray-500 mono mb-6 max-w-md mx-auto">
            Create watchlists from the CVEs page to monitor specific threats
          </p>
          <button
            onClick={() => onNavigate('cves')}
            className="inline-flex items-center px-5 py-3 rounded-lg border transition-all hover:border-cyan-500"
            style={{
              background: 'rgba(6, 182, 212, 0.1)',
              borderColor: 'var(--cyber-accent)',
              color: 'var(--cyber-accent)'
            }}
          >
            <Plus className="h-4 w-4 mr-2" strokeWidth={1.5} />
            <span className="mono text-sm font-medium">CREATE FIRST WATCHLIST</span>
          </button>
        </div>
      )}
    </div>
  );
};

export default Watchlists;
