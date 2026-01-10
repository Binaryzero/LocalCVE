import React, { useState, useEffect } from 'react';
import { Bookmark, Plus, Check, X, Zap, Shield, AlertTriangle, Clock, Eye, Calendar } from 'lucide-react';
import { QueryModel, FilterPreset } from '../types';

const STORAGE_KEY = 'localcve_filter_presets';

// Default presets - must match Settings.tsx
const DEFAULT_PRESETS: FilterPreset[] = [
  {
    id: 'default_today',
    name: 'Today',
    query: { published_relative: 'today' },
    icon: 'calendar',
    color: 'green'
  },
  {
    id: 'default_critical',
    name: 'Critical Only',
    query: { cvss_min: 9.0 },
    icon: 'zap',
    color: 'red'
  },
  {
    id: 'default_high_recent',
    name: 'High + Recent',
    query: { cvss_min: 7.0 },
    icon: 'clock',
    color: 'amber'
  },
  {
    id: 'default_kev',
    name: 'Known Exploited',
    query: { kev: true },
    icon: 'shield',
    color: 'purple'
  }
];

// Icon mapping
const ICONS: Record<string, React.ComponentType<{ className?: string; strokeWidth?: number }>> = {
  'zap': Zap,
  'shield': Shield,
  'alert-triangle': AlertTriangle,
  'clock': Clock,
  'eye': Eye,
  'calendar': Calendar,
};

// Color classes
const getColorClasses = (color: string, isActive: boolean) => {
  const colors: Record<string, { border: string; bg: string; text: string }> = {
    cyan: { border: 'border-cyan-500', bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
    red: { border: 'border-red-500', bg: 'bg-red-500/20', text: 'text-red-400' },
    amber: { border: 'border-amber-500', bg: 'bg-amber-500/20', text: 'text-amber-400' },
    green: { border: 'border-green-500', bg: 'bg-green-500/20', text: 'text-green-400' },
    purple: { border: 'border-purple-500', bg: 'bg-purple-500/20', text: 'text-purple-400' },
    blue: { border: 'border-blue-500', bg: 'bg-blue-500/20', text: 'text-blue-400' },
    pink: { border: 'border-pink-500', bg: 'bg-pink-500/20', text: 'text-pink-400' },
    gray: { border: 'border-gray-500', bg: 'bg-gray-500/20', text: 'text-gray-400' },
  };
  const c = colors[color] || colors.cyan;
  return isActive
    ? `${c.border} ${c.bg} ${c.text}`
    : `border-gray-700 ${c.text} hover:${c.border}`;
};

interface FilterPresetsProps {
  currentFilters: QueryModel;
  onApplyPreset: (query: QueryModel) => void;
}

const FilterPresets: React.FC<FilterPresetsProps> = ({ currentFilters, onApplyPreset }) => {
  const [presets, setPresets] = useState<FilterPreset[]>([]);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [newPresetName, setNewPresetName] = useState('');

  // Load presets from localStorage
  const loadPresets = () => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setPresets(JSON.parse(stored));
      } else {
        // First run - use default presets
        setPresets(DEFAULT_PRESETS);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULT_PRESETS));
      }
    } catch (e) {
      console.error('Failed to load presets:', e);
      setPresets(DEFAULT_PRESETS);
    }
  };

  // Load on mount and listen for storage changes (sync with Settings)
  useEffect(() => {
    loadPresets();

    // Listen for localStorage changes from other components (Settings)
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) {
        loadPresets();
      }
    };

    // Also listen for custom event for same-tab updates
    const handlePresetUpdate = () => {
      loadPresets();
    };

    window.addEventListener('storage', handleStorageChange);
    window.addEventListener('presets-updated', handlePresetUpdate);

    return () => {
      window.removeEventListener('storage', handleStorageChange);
      window.removeEventListener('presets-updated', handlePresetUpdate);
    };
  }, []);

  // Save presets to localStorage
  const savePresetsToStorage = (newPresets: FilterPreset[]) => {
    setPresets(newPresets);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newPresets));
      // Dispatch custom event for same-tab sync
      window.dispatchEvent(new Event('presets-updated'));
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
      isBuiltIn: false,
      color: 'cyan',
      icon: 'zap'
    };

    savePresetsToStorage([...presets, newPreset]);
    setNewPresetName('');
    setShowSaveDialog(false);
  };

  // Check if current filters match a preset
  const isPresetActive = (preset: FilterPreset): boolean => {
    const keys = ['text', 'cvss_min', 'cvss_max', 'kev', 'published_from', 'published_to', 'published_relative'] as const;
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
      <div className="flex items-center gap-2 text-gray-400">
        <Bookmark className="h-4 w-4" strokeWidth={1.5} />
        <span className="mono text-xs font-semibold">FILTER PRESETS</span>
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

      {/* Preset Grid - now with colors and icons */}
      <div className="flex flex-wrap gap-2">
        {presets.map(preset => {
          const isActive = isPresetActive(preset);
          const color = preset.color || 'cyan';
          const IconComp = ICONS[preset.icon || 'zap'] || Zap;
          const colorClasses = getColorClasses(color, isActive);

          return (
            <button
              key={preset.id}
              onClick={() => onApplyPreset(preset.query)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-all mono text-xs font-medium ${colorClasses}`}
            >
              <IconComp className="h-3.5 w-3.5" strokeWidth={1.5} />
              {preset.name}
            </button>
          );
        })}
      </div>

      {/* Preset Info */}
      {presets.length === 0 && (
        <p className="text-xs text-gray-600 mono">
          Save your current filters to create presets
        </p>
      )}
    </div>
  );
};

export default FilterPresets;
