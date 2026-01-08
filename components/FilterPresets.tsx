import React, { useState, useEffect } from 'react';
import { Bookmark, Plus, Trash2, Check, X, Zap } from 'lucide-react';
import { QueryModel, FilterPreset } from '../types';

const STORAGE_KEY = 'localcve_filter_presets';

// Built-in presets that cannot be deleted
const BUILT_IN_PRESETS: FilterPreset[] = [
  {
    id: 'builtin_critical',
    name: 'Critical Only',
    query: { cvss_min: 9.0 },
    isBuiltIn: true
  },
  {
    id: 'builtin_high_recent',
    name: 'High + Recent',
    query: {
      cvss_min: 7.0,
      published_from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
    },
    isBuiltIn: true
  },
  {
    id: 'builtin_kev',
    name: 'Known Exploited',
    query: { kev: true },
    isBuiltIn: true
  }
];

interface FilterPresetsProps {
  currentFilters: QueryModel;
  onApplyPreset: (query: QueryModel) => void;
}

const FilterPresets: React.FC<FilterPresetsProps> = ({ currentFilters, onApplyPreset }) => {
  const [customPresets, setCustomPresets] = useState<FilterPreset[]>([]);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [newPresetName, setNewPresetName] = useState('');

  // Load custom presets from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setCustomPresets(JSON.parse(stored));
      }
    } catch (e) {
      console.error('Failed to load presets:', e);
    }
  }, []);

  // Save custom presets to localStorage
  const savePresets = (presets: FilterPreset[]) => {
    setCustomPresets(presets);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(presets));
    } catch (e) {
      console.error('Failed to save presets:', e);
    }
  };

  const handleSavePreset = () => {
    if (!newPresetName.trim()) return;

    const newPreset: FilterPreset = {
      id: `custom_${Date.now()}`,
      name: newPresetName.trim(),
      query: { ...currentFilters },
      isBuiltIn: false
    };

    savePresets([...customPresets, newPreset]);
    setNewPresetName('');
    setShowSaveDialog(false);
  };

  const handleDeletePreset = (id: string) => {
    savePresets(customPresets.filter(p => p.id !== id));
  };

  const allPresets = [...BUILT_IN_PRESETS, ...customPresets];

  // Check if current filters match a preset
  const isPresetActive = (preset: FilterPreset): boolean => {
    const keys = ['text', 'cvss_min', 'cvss_max', 'kev', 'published_from', 'published_to'] as const;
    return keys.every(key => {
      const presetVal = preset.query[key];
      const filterVal = currentFilters[key];
      // Treat undefined and falsy (0, false, '') as equivalent for comparison
      if (!presetVal && !filterVal) return true;
      return presetVal === filterVal;
    });
  };

  const hasActiveFilters = Object.values(currentFilters).some(v => v !== undefined && v !== '' && v !== 0 && v !== false);

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-gray-400">
          <Bookmark className="h-4 w-4" strokeWidth={1.5} />
          <span className="mono text-xs font-semibold">FILTER PRESETS</span>
        </div>
        {hasActiveFilters && (
          <button
            onClick={() => setShowSaveDialog(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-gray-700 text-gray-400 hover:border-cyan-500 hover:text-cyan-400 transition-all mono text-xs"
          >
            <Plus className="h-3.5 w-3.5" strokeWidth={1.5} />
            SAVE
          </button>
        )}
      </div>

      {/* Save Dialog */}
      {showSaveDialog && (
        <div className="p-3 rounded-lg border bg-gray-900/50" style={{ borderColor: 'var(--cyber-accent)' }}>
          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Preset name..."
              className="flex-1 px-3 py-2 rounded-lg border bg-gray-900/50 text-gray-100 placeholder-gray-600 mono text-sm focus:outline-none focus:border-cyan-500"
              style={{ borderColor: 'var(--cyber-border)' }}
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
              onClick={() => { setShowSaveDialog(false); setNewPresetName(''); }}
              className="p-2 rounded-lg border border-gray-700 text-gray-400 hover:border-gray-600 transition-all"
            >
              <X className="h-4 w-4" strokeWidth={1.5} />
            </button>
          </div>
        </div>
      )}

      {/* Preset Grid */}
      <div className="flex flex-wrap gap-2">
        {allPresets.map(preset => {
          const isActive = isPresetActive(preset);
          return (
            <div
              key={preset.id}
              className={`group flex items-center gap-1 pr-1 rounded-lg border transition-all ${
                isActive
                  ? 'border-cyan-500 bg-cyan-500/20'
                  : 'border-gray-700 hover:border-gray-600'
              }`}
            >
              <button
                onClick={() => onApplyPreset(preset.query)}
                className={`flex items-center gap-2 px-3 py-1.5 mono text-xs font-medium transition-colors ${
                  isActive ? 'text-cyan-400' : 'text-gray-400 hover:text-gray-300'
                }`}
              >
                {preset.isBuiltIn && <Zap className="h-3 w-3" strokeWidth={1.5} />}
                {preset.name}
              </button>
              {!preset.isBuiltIn && (
                <button
                  onClick={(e) => { e.stopPropagation(); handleDeletePreset(preset.id); }}
                  className="p-1 rounded text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
                >
                  <Trash2 className="h-3 w-3" strokeWidth={1.5} />
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* Preset Info */}
      {allPresets.length === BUILT_IN_PRESETS.length && (
        <p className="text-xs text-gray-600 mono">
          Save your current filters to create custom presets
        </p>
      )}
    </div>
  );
};

export default FilterPresets;
