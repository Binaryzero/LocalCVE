import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Eye, EyeOff, Bookmark, Plus, Trash2, Edit3, Check, X, AlertTriangle, Zap, Shield, Clock, Calendar } from 'lucide-react';
import { AppSettings, FilterPreset, QueryModel } from '../types';

const SETTINGS_KEY = 'localcve_settings';
const PRESETS_KEY = 'localcve_filter_presets';

// Available colors for presets
const PRESET_COLORS = [
  { id: 'cyan', label: 'Cyan', class: 'cyan' },
  { id: 'red', label: 'Red', class: 'red' },
  { id: 'amber', label: 'Amber', class: 'amber' },
  { id: 'green', label: 'Green', class: 'green' },
  { id: 'purple', label: 'Purple', class: 'purple' },
  { id: 'blue', label: 'Blue', class: 'blue' },
  { id: 'pink', label: 'Pink', class: 'pink' },
  { id: 'gray', label: 'Gray', class: 'gray' },
];

// Available icons for presets
const PRESET_ICONS = [
  { id: 'zap', label: 'Lightning', Icon: Zap },
  { id: 'shield', label: 'Shield', Icon: Shield },
  { id: 'alert-triangle', label: 'Warning', Icon: AlertTriangle },
  { id: 'clock', label: 'Clock', Icon: Clock },
  { id: 'eye', label: 'Eye', Icon: Eye },
  { id: 'calendar', label: 'Calendar', Icon: Calendar },
];

// Default presets to restore
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

interface SettingsProps {
  settings: AppSettings;
  onSettingsChange: (settings: AppSettings) => void;
}

const Settings: React.FC<SettingsProps> = ({ settings, onSettingsChange }) => {
  const [presets, setPresets] = useState<FilterPreset[]>([]);
  const [editingPreset, setEditingPreset] = useState<FilterPreset | null>(null);
  const [showAddPreset, setShowAddPreset] = useState(false);
  const [newPresetName, setNewPresetName] = useState('');
  const [newPresetColor, setNewPresetColor] = useState('cyan');
  const [newPresetIcon, setNewPresetIcon] = useState('zap');

  // Load presets from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem(PRESETS_KEY);
      if (stored) {
        setPresets(JSON.parse(stored));
      } else {
        // First run - use default presets
        setPresets(DEFAULT_PRESETS);
        localStorage.setItem(PRESETS_KEY, JSON.stringify(DEFAULT_PRESETS));
      }
    } catch (e) {
      console.error('Failed to load presets:', e);
      setPresets(DEFAULT_PRESETS);
    }
  }, []);

  const savePresets = (newPresets: FilterPreset[]) => {
    setPresets(newPresets);
    try {
      localStorage.setItem(PRESETS_KEY, JSON.stringify(newPresets));
      // Dispatch custom event for same-tab sync with FilterPresets component
      window.dispatchEvent(new Event('presets-updated'));
    } catch (e) {
      console.error('Failed to save presets:', e);
    }
  };

  const handleDeletePreset = (id: string) => {
    savePresets(presets.filter(p => p.id !== id));
  };

  const handleRestoreDefaults = () => {
    // Keep all custom presets (non-default IDs)
    const customPresets = presets.filter(p => !p.id.startsWith('default_'));
    // Restore default presets to their original state + keep custom presets
    savePresets([...DEFAULT_PRESETS, ...customPresets]);
  };

  const handleUpdatePreset = (preset: FilterPreset) => {
    savePresets(presets.map(p => p.id === preset.id ? preset : p));
    setEditingPreset(null);
  };

  const handleAddPreset = () => {
    if (!newPresetName.trim()) return;
    const newPreset: FilterPreset = {
      id: `custom_${Date.now()}`,
      name: newPresetName.trim(),
      query: {},
      icon: newPresetIcon,
      color: newPresetColor
    };
    savePresets([...presets, newPreset]);
    setNewPresetName('');
    setShowAddPreset(false);
  };

  const getColorClasses = (color: string, active: boolean = false) => {
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
    return active ? `${c.border} ${c.bg} ${c.text}` : `border-gray-700 ${c.text}`;
  };

  const getIconComponent = (iconId: string | undefined) => {
    const icon = PRESET_ICONS.find(i => i.id === iconId);
    return icon?.Icon || Zap;
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="relative">
          <SettingsIcon className="h-8 w-8 text-cyan-400" strokeWidth={1.5} />
          <div className="absolute inset-0 bg-cyan-400/20 blur-xl rounded-full" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-gray-100 mono">Settings</h1>
          <p className="text-sm text-gray-500">Configure application preferences</p>
        </div>
      </div>

      {/* CVE Display Settings */}
      <div className="rounded-lg border p-6" style={{ background: 'var(--cyber-surface)', borderColor: 'var(--cyber-border)' }}>
        <h2 className="text-lg font-semibold text-gray-100 mb-4 flex items-center gap-2">
          <Eye className="h-5 w-5 text-cyan-400" strokeWidth={1.5} />
          CVE Display
        </h2>
        <div className="space-y-4">
          <label className="flex items-center gap-3 cursor-pointer group">
            <input
              type="checkbox"
              checked={!settings.hideRejectedCves}
              onChange={(e) => onSettingsChange({ ...settings, hideRejectedCves: !e.target.checked })}
              className="w-5 h-5 rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-0"
            />
            <div>
              <span className="text-gray-200 group-hover:text-gray-100">Show Rejected CVEs</span>
              <p className="text-xs text-gray-500">Include CVEs with REJECTED status in search results</p>
            </div>
          </label>
          <label className="flex items-center gap-3 cursor-pointer group">
            <input
              type="checkbox"
              checked={settings.hideDisputedCves}
              onChange={(e) => onSettingsChange({ ...settings, hideDisputedCves: e.target.checked })}
              className="w-5 h-5 rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-0"
            />
            <div>
              <span className="text-gray-200 group-hover:text-gray-100">Hide Disputed CVEs</span>
              <p className="text-xs text-gray-500">CVEs with DISPUTED status will not appear in search results</p>
            </div>
          </label>
        </div>
      </div>

      {/* Filter Presets Management */}
      <div className="rounded-lg border p-6" style={{ background: 'var(--cyber-surface)', borderColor: 'var(--cyber-border)' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Bookmark className="h-5 w-5 text-cyan-400" strokeWidth={1.5} />
            Filter Presets
          </h2>
          <div className="flex gap-2">
            <button
              onClick={handleRestoreDefaults}
              className="px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-all mono text-xs"
            >
              Restore Defaults
            </button>
            <button
              onClick={() => setShowAddPreset(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500 bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-all mono text-xs"
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={1.5} />
              Add Preset
            </button>
          </div>
        </div>

        {/* Add Preset Dialog */}
        {showAddPreset && (
          <div className="mb-4 p-4 rounded-lg border bg-gray-900/50" style={{ borderColor: 'var(--cyber-accent)' }}>
            <h3 className="text-sm font-semibold text-gray-200 mb-3">New Preset</h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-gray-500 mb-1">Name</label>
                <input
                  type="text"
                  value={newPresetName}
                  onChange={(e) => setNewPresetName(e.target.value)}
                  placeholder="Preset name..."
                  className="w-full px-3 py-2 rounded-lg border bg-gray-900/50 text-gray-100 placeholder-gray-600 mono text-sm focus:outline-none focus:border-cyan-500"
                  style={{ borderColor: 'var(--cyber-border)' }}
                  autoFocus
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Color</label>
                  <div className="flex flex-wrap gap-1">
                    {PRESET_COLORS.map(color => (
                      <button
                        key={color.id}
                        onClick={() => setNewPresetColor(color.id)}
                        className={`w-6 h-6 rounded border-2 transition-all ${
                          newPresetColor === color.id ? getColorClasses(color.id, true) : 'border-gray-700'
                        }`}
                        style={{ backgroundColor: `var(--tw-${color.id}-500, currentColor)` }}
                        title={color.label}
                      >
                        <span className={`block w-full h-full rounded-sm ${getColorClasses(color.id, true).split(' ')[1]}`} />
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Icon</label>
                  <div className="flex flex-wrap gap-1">
                    {PRESET_ICONS.map(icon => {
                      const IconComp = icon.Icon;
                      return (
                        <button
                          key={icon.id}
                          onClick={() => setNewPresetIcon(icon.id)}
                          className={`p-1.5 rounded border transition-all ${
                            newPresetIcon === icon.id
                              ? 'border-cyan-500 bg-cyan-500/20 text-cyan-400'
                              : 'border-gray-700 text-gray-500 hover:text-gray-400'
                          }`}
                          title={icon.label}
                        >
                          <IconComp className="h-4 w-4" strokeWidth={1.5} />
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  onClick={() => { setShowAddPreset(false); setNewPresetName(''); }}
                  className="px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-300 transition-all mono text-xs"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddPreset}
                  disabled={!newPresetName.trim()}
                  className="px-3 py-1.5 rounded-lg border border-cyan-500 bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-all mono text-xs disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Create Preset
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Preset List */}
        <div className="space-y-2">
          {presets.length === 0 ? (
            <p className="text-sm text-gray-500 text-center py-4">No presets configured</p>
          ) : (
            presets.map(preset => {
              const IconComp = getIconComponent(preset.icon);
              const color = preset.color || 'cyan';
              const isEditing = editingPreset?.id === preset.id;

              if (isEditing) {
                return (
                  <div key={preset.id} className="p-3 rounded-lg border bg-gray-900/50" style={{ borderColor: 'var(--cyber-accent)' }}>
                    <div className="space-y-3">
                      <input
                        type="text"
                        value={editingPreset.name}
                        onChange={(e) => setEditingPreset({ ...editingPreset, name: e.target.value })}
                        className="w-full px-3 py-2 rounded-lg border bg-gray-900/50 text-gray-100 mono text-sm focus:outline-none focus:border-cyan-500"
                        style={{ borderColor: 'var(--cyber-border)' }}
                        placeholder="Preset name"
                      />

                      {/* Query Editor */}
                      <div className="p-2 rounded border bg-gray-900/30" style={{ borderColor: 'var(--cyber-border)' }}>
                        <label className="block text-xs text-gray-500 mb-2">Filter Query</label>
                        <div className="grid grid-cols-2 gap-2">
                          <div>
                            <label className="block text-xs text-gray-600 mb-1">Search Text</label>
                            <input
                              type="text"
                              value={editingPreset.query.text || ''}
                              onChange={(e) => setEditingPreset({
                                ...editingPreset,
                                query: { ...editingPreset.query, text: e.target.value || undefined }
                              })}
                              className="w-full px-2 py-1 rounded border bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500"
                              style={{ borderColor: 'var(--cyber-border)' }}
                              placeholder="e.g., apache"
                            />
                          </div>
                          <div>
                            <label className="block text-xs text-gray-600 mb-1">Min CVSS</label>
                            <input
                              type="number"
                              min="0"
                              max="10"
                              step="0.1"
                              value={editingPreset.query.cvss_min || ''}
                              onChange={(e) => setEditingPreset({
                                ...editingPreset,
                                query: { ...editingPreset.query, cvss_min: e.target.value ? parseFloat(e.target.value) : undefined }
                              })}
                              className="w-full px-2 py-1 rounded border bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500"
                              style={{ borderColor: 'var(--cyber-border)' }}
                              placeholder="0-10"
                            />
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-2 mt-2">
                          <div>
                            <label className="block text-xs text-gray-600 mb-1">Published</label>
                            <select
                              value={editingPreset.query.published_relative || ''}
                              onChange={(e) => setEditingPreset({
                                ...editingPreset,
                                query: { ...editingPreset.query, published_relative: e.target.value || undefined }
                              })}
                              className="w-full px-2 py-1 rounded border bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500"
                              style={{ borderColor: 'var(--cyber-border)' }}
                            >
                              <option value="">Any date</option>
                              <option value="today">Today</option>
                              <option value="last_7_days">Last 7 Days</option>
                              <option value="last_30_days">Last 30 Days</option>
                              <option value="last_90_days">Last 90 Days</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-xs text-gray-600 mb-1">Modified</label>
                            <select
                              value={editingPreset.query.modified_relative || ''}
                              onChange={(e) => setEditingPreset({
                                ...editingPreset,
                                query: { ...editingPreset.query, modified_relative: e.target.value || undefined }
                              })}
                              className="w-full px-2 py-1 rounded border bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500"
                              style={{ borderColor: 'var(--cyber-border)' }}
                            >
                              <option value="">Any date</option>
                              <option value="today">Today</option>
                              <option value="last_7_days">Last 7 Days</option>
                              <option value="last_30_days">Last 30 Days</option>
                              <option value="last_90_days">Last 90 Days</option>
                            </select>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-2 mt-2">
                          <div>
                            <label className="block text-xs text-gray-600 mb-1">Vendors</label>
                            <input
                              type="text"
                              value={(editingPreset.query.vendors || []).join(', ')}
                              onChange={(e) => {
                                const vendors = e.target.value.split(',').map(v => v.trim()).filter(v => v);
                                setEditingPreset({
                                  ...editingPreset,
                                  query: { ...editingPreset.query, vendors: vendors.length > 0 ? vendors : undefined }
                                });
                              }}
                              className="w-full px-2 py-1 rounded border bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500"
                              style={{ borderColor: 'var(--cyber-border)' }}
                              placeholder="e.g., apache, microsoft"
                            />
                          </div>
                          <div>
                            <label className="block text-xs text-gray-600 mb-1">Products</label>
                            <input
                              type="text"
                              value={(editingPreset.query.products || []).join(', ')}
                              onChange={(e) => {
                                const products = e.target.value.split(',').map(p => p.trim()).filter(p => p);
                                setEditingPreset({
                                  ...editingPreset,
                                  query: { ...editingPreset.query, products: products.length > 0 ? products : undefined }
                                });
                              }}
                              className="w-full px-2 py-1 rounded border bg-gray-900/50 text-gray-100 mono text-xs focus:outline-none focus:border-cyan-500"
                              style={{ borderColor: 'var(--cyber-border)' }}
                              placeholder="e.g., log4j, windows"
                            />
                          </div>
                        </div>
                        <div className="flex items-center mt-2">
                          <label className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={editingPreset.query.kev || false}
                              onChange={(e) => setEditingPreset({
                                ...editingPreset,
                                query: { ...editingPreset.query, kev: e.target.checked || undefined }
                              })}
                              className="w-3 h-3 rounded bg-gray-900 border-gray-700"
                            />
                            <span className="text-xs text-gray-400 mono">KEV Only</span>
                          </label>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs text-gray-500 mb-1">Color</label>
                          <div className="flex flex-wrap gap-1">
                            {PRESET_COLORS.map(c => (
                              <button
                                key={c.id}
                                onClick={() => setEditingPreset({ ...editingPreset, color: c.id })}
                                className={`w-6 h-6 rounded border-2 transition-all ${
                                  editingPreset.color === c.id ? getColorClasses(c.id, true) : 'border-gray-700'
                                }`}
                                title={c.label}
                              >
                                <span className={`block w-full h-full rounded-sm ${getColorClasses(c.id, true).split(' ')[1]}`} />
                              </button>
                            ))}
                          </div>
                        </div>
                        <div>
                          <label className="block text-xs text-gray-500 mb-1">Icon</label>
                          <div className="flex flex-wrap gap-1">
                            {PRESET_ICONS.map(icon => {
                              const IC = icon.Icon;
                              return (
                                <button
                                  key={icon.id}
                                  onClick={() => setEditingPreset({ ...editingPreset, icon: icon.id })}
                                  className={`p-1.5 rounded border transition-all ${
                                    editingPreset.icon === icon.id
                                      ? 'border-cyan-500 bg-cyan-500/20 text-cyan-400'
                                      : 'border-gray-700 text-gray-500'
                                  }`}
                                  title={icon.label}
                                >
                                  <IC className="h-4 w-4" strokeWidth={1.5} />
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => setEditingPreset(null)}
                          className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-300"
                        >
                          <X className="h-4 w-4" strokeWidth={1.5} />
                        </button>
                        <button
                          onClick={() => handleUpdatePreset(editingPreset)}
                          className="p-1.5 rounded border border-cyan-500 bg-cyan-500/20 text-cyan-400"
                        >
                          <Check className="h-4 w-4" strokeWidth={1.5} />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              }

              return (
                <div
                  key={preset.id}
                  className={`flex items-center justify-between p-3 rounded-lg border transition-all ${getColorClasses(color, false)}`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`p-1.5 rounded ${getColorClasses(color, true)}`}>
                      <IconComp className="h-4 w-4" strokeWidth={1.5} />
                    </div>
                    <div>
                      <span className="text-gray-200 font-medium">{preset.name}</span>
                      <p className="text-xs text-gray-500">
                        {Object.entries(preset.query).filter(([_, v]) => v !== undefined && v !== '').map(([k, v]) =>
                          `${k}: ${typeof v === 'boolean' ? (v ? 'Yes' : 'No') : v}`
                        ).join(', ') || 'No filters'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setEditingPreset(preset)}
                      className="p-1.5 rounded text-gray-500 hover:text-cyan-400 transition-all"
                      title="Edit preset"
                    >
                      <Edit3 className="h-4 w-4" strokeWidth={1.5} />
                    </button>
                    <button
                      onClick={() => handleDeletePreset(preset.id)}
                      className="p-1.5 rounded text-gray-500 hover:text-red-400 transition-all"
                      title="Delete preset"
                    >
                      <Trash2 className="h-4 w-4" strokeWidth={1.5} />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

export default Settings;
