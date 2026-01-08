import React, { useState } from 'react';
import { Eye, Trash2, Plus, ToggleLeft, ToggleRight, Target, ExternalLink, Pencil, Check, X } from 'lucide-react';
import { Watchlist, QueryModel } from '../types';
import QueryVisualizer from './QueryVisualizer';

interface WatchlistsProps {
  watchlists: Watchlist[];
  onToggle: (id: string) => void;
  onDelete: (id: string) => void;
  onUpdate: (id: string, updates: { name?: string; query?: QueryModel }) => void;
  onNavigate: (page: string) => void;
  onApplyFilter?: (filter: QueryModel) => void;
}

const Watchlists: React.FC<WatchlistsProps> = ({ watchlists, onToggle, onDelete, onUpdate, onNavigate, onApplyFilter }) => {
  const [editingNameId, setEditingNameId] = useState<string | null>(null);
  const [editingQueryId, setEditingQueryId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const [editQuery, setEditQuery] = useState<QueryModel>({});

  const startEditingName = (wl: Watchlist) => {
    setEditingNameId(wl.id);
    setEditName(wl.name);
  };

  const saveName = (id: string) => {
    if (editName.trim()) {
      onUpdate(id, { name: editName.trim() });
    }
    setEditingNameId(null);
    setEditName('');
  };

  const cancelEditName = () => {
    setEditingNameId(null);
    setEditName('');
  };

  const startEditingQuery = (wl: Watchlist) => {
    setEditingQueryId(wl.id);
    setEditQuery({ ...wl.query });
  };

  const saveQuery = (id: string) => {
    onUpdate(id, { query: editQuery });
    setEditingQueryId(null);
    setEditQuery({});
  };

  const cancelEditQuery = () => {
    setEditingQueryId(null);
    setEditQuery({});
  };

  const handleChipClick = (filter: Partial<QueryModel>) => {
    if (onApplyFilter) {
      onApplyFilter(filter as QueryModel);
      onNavigate('cves');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h1 className="text-3xl font-bold text-gray-100 mono tracking-tight">WATCHLISTS</h1>
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
                    <div className="flex-1">
                      {editingNameId === wl.id ? (
                        <div className="flex items-center gap-2">
                          <input
                            type="text"
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') saveName(wl.id);
                              if (e.key === 'Escape') cancelEditName();
                            }}
                            className="px-2 py-1 rounded border bg-gray-900 text-gray-100 mono text-lg font-semibold focus:outline-none focus:border-cyan-500"
                            style={{ borderColor: 'var(--cyber-border)' }}
                            autoFocus
                          />
                          <button
                            onClick={() => saveName(wl.id)}
                            className="p-1 rounded hover:bg-cyan-500/20 text-cyan-400"
                          >
                            <Check className="h-4 w-4" strokeWidth={2} />
                          </button>
                          <button
                            onClick={cancelEditName}
                            className="p-1 rounded hover:bg-gray-700 text-gray-400"
                          >
                            <X className="h-4 w-4" strokeWidth={2} />
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => startEditingName(wl)}
                          className="group/name flex items-center gap-2 hover:text-cyan-400 transition-colors"
                        >
                          <h3 className="text-lg font-semibold text-gray-100 group-hover/name:text-cyan-400 mono">{wl.name}</h3>
                          <Pencil className="h-3.5 w-3.5 text-gray-600 opacity-0 group-hover/name:opacity-100 transition-opacity" strokeWidth={1.5} />
                        </button>
                      )}
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
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs font-semibold text-gray-500 mono uppercase">
                      Query
                    </label>
                    <div className="flex items-center gap-2">
                      {editingQueryId !== wl.id && (
                        <button
                          onClick={() => startEditingQuery(wl)}
                          className="flex items-center gap-1 text-xs text-gray-400 hover:text-cyan-400 mono transition-colors"
                          title="Edit query"
                        >
                          <Pencil className="h-3 w-3" strokeWidth={1.5} />
                          EDIT
                        </button>
                      )}
                      {onApplyFilter && editingQueryId !== wl.id && (
                        <button
                          onClick={() => { onApplyFilter(wl.query); onNavigate('cves'); }}
                          className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 mono transition-colors"
                          title="Apply this filter to CVE search"
                        >
                          <ExternalLink className="h-3 w-3" strokeWidth={1.5} />
                          SEARCH
                        </button>
                      )}
                    </div>
                  </div>

                  {editingQueryId === wl.id ? (
                    <div className="space-y-3 p-3 rounded-lg border" style={{ borderColor: 'var(--cyber-accent)', background: 'rgba(6, 182, 212, 0.05)' }}>
                      {/* Text Search */}
                      <div>
                        <label className="text-xs text-gray-500 mono mb-1 block">SEARCH TEXT</label>
                        <input
                          type="text"
                          value={editQuery.text || ''}
                          onChange={(e) => setEditQuery({ ...editQuery, text: e.target.value || undefined })}
                          placeholder="CVE ID or description..."
                          className="w-full px-3 py-2 rounded border bg-gray-900 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                          style={{ borderColor: 'var(--cyber-border)' }}
                        />
                      </div>

                      {/* CVSS Min */}
                      <div>
                        <label className="text-xs text-gray-500 mono mb-1 block">CVSS MIN</label>
                        <input
                          type="number"
                          min="0"
                          max="10"
                          step="0.1"
                          value={editQuery.cvss_min || ''}
                          onChange={(e) => setEditQuery({ ...editQuery, cvss_min: e.target.value ? parseFloat(e.target.value) : undefined })}
                          placeholder="0.0"
                          className="w-full px-3 py-2 rounded border bg-gray-900 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                          style={{ borderColor: 'var(--cyber-border)' }}
                        />
                      </div>

                      {/* KEV Only */}
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          id={`kev-${wl.id}`}
                          checked={editQuery.kev || false}
                          onChange={(e) => setEditQuery({ ...editQuery, kev: e.target.checked || undefined })}
                          className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-cyan-500 focus:ring-cyan-500"
                        />
                        <label htmlFor={`kev-${wl.id}`} className="text-sm text-gray-300 mono">Known Exploited Only</label>
                      </div>

                      {/* Date Range */}
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <label className="text-xs text-gray-500 mono mb-1 block">FROM DATE</label>
                          <input
                            type="date"
                            value={editQuery.published_from || ''}
                            onChange={(e) => setEditQuery({ ...editQuery, published_from: e.target.value || undefined })}
                            className="w-full px-3 py-2 rounded border bg-gray-900 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                            style={{ borderColor: 'var(--cyber-border)' }}
                          />
                        </div>
                        <div>
                          <label className="text-xs text-gray-500 mono mb-1 block">TO DATE</label>
                          <input
                            type="date"
                            value={editQuery.published_to || ''}
                            onChange={(e) => setEditQuery({ ...editQuery, published_to: e.target.value || undefined })}
                            className="w-full px-3 py-2 rounded border bg-gray-900 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                            style={{ borderColor: 'var(--cyber-border)' }}
                          />
                        </div>
                      </div>

                      {/* Save/Cancel */}
                      <div className="flex items-center justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--cyber-border)' }}>
                        <button
                          onClick={cancelEditQuery}
                          className="px-3 py-1.5 rounded border text-gray-400 hover:text-gray-300 mono text-xs transition-colors"
                          style={{ borderColor: 'var(--cyber-border)' }}
                        >
                          CANCEL
                        </button>
                        <button
                          onClick={() => saveQuery(wl.id)}
                          className="px-3 py-1.5 rounded border border-cyan-500 bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 mono text-xs transition-colors"
                        >
                          SAVE QUERY
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div
                      className="p-3 rounded-lg border"
                      style={{
                        background: 'rgba(6, 182, 212, 0.03)',
                        borderColor: 'var(--cyber-border)'
                      }}
                    >
                      <QueryVisualizer
                        query={wl.query}
                        onChipClick={onApplyFilter ? handleChipClick : undefined}
                      />
                    </div>
                  )}
                </div>

                {/* Alert count */}
                <div className="flex items-center justify-between pt-3 border-t" style={{ borderColor: 'var(--cyber-border)' }}>
                  <span className="text-xs text-gray-500 mono">ALERTS GENERATED</span>
                  <span className="text-lg font-bold text-cyan-400 mono">{wl.matchCount || 0}</span>
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
            Create watchlists from the CVEs page to track CVEs matching specific criteria
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
