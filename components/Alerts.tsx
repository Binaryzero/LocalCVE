import React, { useState, useMemo } from 'react';
import { Bell, Check, Trash2, Calendar, AlertCircle, CheckCheck, Trash, Download, ChevronDown, ChevronRight, Layers, Clock, Square, CheckSquare, MinusSquare } from 'lucide-react';
import { Alert } from '../types';

type GroupingMode = 'none' | 'watchlist' | 'date';

interface AlertsProps {
  alerts: Alert[];
  onMarkRead: (id: string) => void;
  onDelete: (id: string) => void;
  onMarkAllRead?: () => void;
  onDeleteAll?: () => void;
  onViewCve?: (id: string) => void;
  onBulkMarkRead?: (ids: string[]) => void;
  onBulkDelete?: (ids: string[]) => void;
}

// Export utilities
const exportToCSV = (alerts: Alert[]) => {
  const headers = ['CVE ID', 'Watchlist', 'Type', 'Date', 'Read'];
  const rows = alerts.map(a => [
    a.cveId,
    a.watchlistName,
    a.type === 'NEW_MATCH' ? 'New' : 'Updated',
    new Date(a.createdAt).toISOString(),
    a.read ? 'Yes' : 'No'
  ]);

  const csv = [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
  downloadFile(csv, 'alerts.csv', 'text/csv');
};

const exportToJSON = (alerts: Alert[]) => {
  const json = JSON.stringify(alerts, null, 2);
  downloadFile(json, 'alerts.json', 'application/json');
};

const downloadFile = (content: string, filename: string, mimeType: string) => {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// Group alerts by different criteria
const groupAlerts = (alerts: Alert[], mode: GroupingMode): Map<string, Alert[]> => {
  if (mode === 'none') {
    return new Map([['all', alerts]]);
  }

  const groups = new Map<string, Alert[]>();

  alerts.forEach(alert => {
    let key: string;
    if (mode === 'watchlist') {
      key = alert.watchlistName;
    } else {
      // Group by date (YYYY-MM-DD)
      key = new Date(alert.createdAt).toISOString().split('T')[0];
    }

    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(alert);
  });

  return groups;
};

const Alerts: React.FC<AlertsProps> = ({
  alerts,
  onMarkRead,
  onDelete,
  onMarkAllRead,
  onDeleteAll,
  onViewCve,
  onBulkMarkRead,
  onBulkDelete
}) => {
  const unreadCount = alerts.filter(a => !a.read).length;
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [groupingMode, setGroupingMode] = useState<GroupingMode>('none');
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showBulkDeleteConfirm, setShowBulkDeleteConfirm] = useState(false);

  // Memoize grouped alerts
  const groupedAlerts = useMemo(() => groupAlerts(alerts, groupingMode), [alerts, groupingMode]);

  // Selection helpers
  const toggleSelect = (id: string) => {
    const newSelected = new Set(selectedIds);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedIds(newSelected);
  };

  const selectAll = () => {
    setSelectedIds(new Set(alerts.map(a => a.id)));
  };

  const selectNone = () => {
    setSelectedIds(new Set());
  };

  const toggleGroup = (groupKey: string) => {
    const newCollapsed = new Set(collapsedGroups);
    if (newCollapsed.has(groupKey)) {
      newCollapsed.delete(groupKey);
    } else {
      newCollapsed.add(groupKey);
    }
    setCollapsedGroups(newCollapsed);
  };

  const handleBulkMarkRead = () => {
    if (onBulkMarkRead) {
      onBulkMarkRead(Array.from(selectedIds));
    } else {
      // Fallback: mark individually
      selectedIds.forEach(id => onMarkRead(id));
    }
    setSelectedIds(new Set());
  };

  const handleBulkDelete = () => {
    if (onBulkDelete) {
      onBulkDelete(Array.from(selectedIds));
    } else {
      // Fallback: delete individually
      selectedIds.forEach(id => onDelete(id));
    }
    setSelectedIds(new Set());
    setShowBulkDeleteConfirm(false);
  };

  // Calculate selection state for "select all" checkbox
  const allSelected = alerts.length > 0 && selectedIds.size === alerts.length;
  const someSelected = selectedIds.size > 0 && selectedIds.size < alerts.length;

  const selectedUnreadCount = alerts.filter(a => selectedIds.has(a.id) && !a.read).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-100 mono tracking-tight">ALERT INBOX</h1>
          <div className="flex items-center space-x-3 mt-2">
            <p className="text-sm text-gray-500 mono">
              {unreadCount} <span className="text-gray-600">UNREAD</span>
            </p>
            <div className="w-1 h-1 bg-gray-600 rounded-full" />
            <p className="text-sm text-gray-500 mono">
              {alerts.length} <span className="text-gray-600">TOTAL</span>
            </p>
            {selectedIds.size > 0 && (
              <>
                <div className="w-1 h-1 bg-cyan-600 rounded-full" />
                <p className="text-sm text-cyan-400 mono">
                  {selectedIds.size} <span className="text-cyan-500">SELECTED</span>
                </p>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {unreadCount > 0 && (
            <div className="flex items-center space-x-2 px-4 py-2 rounded-lg border animate-pulse"
              style={{
                background: 'rgba(239, 68, 68, 0.1)',
                borderColor: '#ef4444'
              }}
            >
              <div className="w-2 h-2 bg-red-400 rounded-full" />
              <span className="text-sm text-red-400 mono font-medium">{unreadCount} NEW</span>
            </div>
          )}

          {/* Grouping Toggle */}
          <div className="flex items-center rounded-lg border overflow-hidden" style={{ borderColor: 'var(--cyber-border)' }}>
            <button
              onClick={() => setGroupingMode('none')}
              className={`px-3 py-2 text-xs mono font-medium transition-all ${
                groupingMode === 'none' ? 'bg-cyan-500/20 text-cyan-400' : 'text-gray-500 hover:text-gray-300'
              }`}
              title="No grouping"
            >
              <Layers className="h-4 w-4" strokeWidth={1.5} />
            </button>
            <button
              onClick={() => setGroupingMode('watchlist')}
              className={`px-3 py-2 text-xs mono font-medium transition-all ${
                groupingMode === 'watchlist' ? 'bg-cyan-500/20 text-cyan-400' : 'text-gray-500 hover:text-gray-300'
              }`}
              title="Group by watchlist"
            >
              WATCHLIST
            </button>
            <button
              onClick={() => setGroupingMode('date')}
              className={`px-3 py-2 text-xs mono font-medium transition-all ${
                groupingMode === 'date' ? 'bg-cyan-500/20 text-cyan-400' : 'text-gray-500 hover:text-gray-300'
              }`}
              title="Group by date"
            >
              <Clock className="h-4 w-4" strokeWidth={1.5} />
            </button>
          </div>

          {/* Export Dropdown */}
          {alerts.length > 0 && (
            <div className="relative">
              <button
                onClick={() => setShowExportMenu(!showExportMenu)}
                className="inline-flex items-center px-3 py-2 rounded-lg border transition-all hover:border-cyan-500 hover:bg-cyan-500/10"
                style={{ borderColor: 'var(--cyber-border)' }}
              >
                <Download className="h-4 w-4 text-gray-400 mr-2" strokeWidth={1.5} />
                <span className="text-sm text-gray-400 mono font-medium">EXPORT</span>
              </button>
              {showExportMenu && (
                <div
                  className="absolute right-0 mt-2 w-32 rounded-lg border shadow-lg z-10"
                  style={{ background: 'var(--cyber-surface)', borderColor: 'var(--cyber-border)' }}
                >
                  <button
                    onClick={() => { exportToCSV(alerts); setShowExportMenu(false); }}
                    className="w-full px-4 py-2 text-sm text-gray-300 mono hover:bg-cyan-500/10 text-left transition-colors"
                  >
                    CSV
                  </button>
                  <button
                    onClick={() => { exportToJSON(alerts); setShowExportMenu(false); }}
                    className="w-full px-4 py-2 text-sm text-gray-300 mono hover:bg-cyan-500/10 text-left transition-colors"
                  >
                    JSON
                  </button>
                </div>
              )}
            </div>
          )}

          {unreadCount > 0 && onMarkAllRead && (
            <button
              onClick={onMarkAllRead}
              className="inline-flex items-center px-3 py-2 rounded-lg border transition-all hover:border-cyan-500 hover:bg-cyan-500/10"
              style={{ borderColor: 'var(--cyber-border)' }}
              title="Mark all as read"
            >
              <CheckCheck className="h-4 w-4 text-cyan-400 mr-2" strokeWidth={1.5} />
              <span className="text-sm text-cyan-400 mono font-medium">MARK ALL READ</span>
            </button>
          )}
          {alerts.length > 0 && onDeleteAll && (
            showDeleteConfirm ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-red-500 bg-red-500/10">
                <span className="text-sm text-red-400 mono">Delete all?</span>
                <button
                  onClick={() => { onDeleteAll(); setShowDeleteConfirm(false); }}
                  className="px-2 py-1 rounded bg-red-500 text-white text-xs mono font-medium hover:bg-red-600 transition-colors"
                >
                  YES
                </button>
                <button
                  onClick={() => setShowDeleteConfirm(false)}
                  className="px-2 py-1 rounded bg-gray-700 text-gray-300 text-xs mono font-medium hover:bg-gray-600 transition-colors"
                >
                  NO
                </button>
              </div>
            ) : (
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="inline-flex items-center px-3 py-2 rounded-lg border transition-all hover:border-red-500 hover:bg-red-500/10"
                style={{ borderColor: 'var(--cyber-border)' }}
                title="Delete all alerts"
              >
                <Trash className="h-4 w-4 text-gray-400 mr-2" strokeWidth={1.5} />
                <span className="text-sm text-gray-400 mono font-medium">DELETE ALL</span>
              </button>
            )
          )}
        </div>
      </div>

      {/* Selection Toolbar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 p-3 rounded-lg border" style={{
          background: 'rgba(6, 182, 212, 0.1)',
          borderColor: 'rgba(6, 182, 212, 0.3)'
        }}>
          <span className="text-sm text-cyan-400 mono font-medium">
            {selectedIds.size} SELECTED
          </span>
          <div className="w-px h-4 bg-cyan-500/30" />
          {selectedUnreadCount > 0 && (
            <button
              onClick={handleBulkMarkRead}
              className="inline-flex items-center px-3 py-1.5 rounded-lg border border-cyan-500/50 bg-cyan-500/10 text-cyan-400 text-xs mono font-medium hover:bg-cyan-500/20 transition-colors"
            >
              <Check className="h-3.5 w-3.5 mr-1.5" strokeWidth={1.5} />
              MARK READ ({selectedUnreadCount})
            </button>
          )}
          {showBulkDeleteConfirm ? (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-red-500 bg-red-500/10">
              <span className="text-xs text-red-400 mono">Delete {selectedIds.size}?</span>
              <button
                onClick={handleBulkDelete}
                className="px-2 py-0.5 rounded bg-red-500 text-white text-xs mono font-medium hover:bg-red-600 transition-colors"
              >
                YES
              </button>
              <button
                onClick={() => setShowBulkDeleteConfirm(false)}
                className="px-2 py-0.5 rounded bg-gray-700 text-gray-300 text-xs mono font-medium hover:bg-gray-600 transition-colors"
              >
                NO
              </button>
            </div>
          ) : (
            <button
              onClick={() => setShowBulkDeleteConfirm(true)}
              className="inline-flex items-center px-3 py-1.5 rounded-lg border border-red-500/50 bg-red-500/10 text-red-400 text-xs mono font-medium hover:bg-red-500/20 transition-colors"
            >
              <Trash2 className="h-3.5 w-3.5 mr-1.5" strokeWidth={1.5} />
              DELETE ({selectedIds.size})
            </button>
          )}
          <button
            onClick={selectNone}
            className="ml-auto text-xs text-gray-500 mono hover:text-gray-300 transition-colors"
          >
            CLEAR SELECTION
          </button>
        </div>
      )}

      {/* Alerts List */}
      {alerts.length > 0 ? (
        <div className="rounded-lg border overflow-hidden" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)'
        }}>
          {/* Select All Header */}
          <div className="flex items-center gap-3 px-6 py-3 border-b" style={{ borderColor: 'var(--cyber-border)' }}>
            <button
              onClick={() => allSelected ? selectNone() : selectAll()}
              className="p-0.5 rounded hover:bg-cyan-500/10 transition-colors"
              title={allSelected ? 'Deselect all' : 'Select all'}
            >
              {allSelected ? (
                <CheckSquare className="h-5 w-5 text-cyan-400" strokeWidth={1.5} />
              ) : someSelected ? (
                <MinusSquare className="h-5 w-5 text-cyan-400" strokeWidth={1.5} />
              ) : (
                <Square className="h-5 w-5 text-gray-500" strokeWidth={1.5} />
              )}
            </button>
            <span className="text-xs text-gray-500 mono">
              {allSelected ? 'DESELECT ALL' : someSelected ? `${selectedIds.size} SELECTED` : 'SELECT ALL'}
            </span>
          </div>

          {/* Grouped or flat list */}
          {groupingMode === 'none' ? (
            <ul className="divide-y" style={{ borderColor: 'var(--cyber-border)' }}>
              {alerts.map((alert) => (
                <AlertRow
                  key={alert.id}
                  alert={alert}
                  isSelected={selectedIds.has(alert.id)}
                  onToggleSelect={toggleSelect}
                  onMarkRead={onMarkRead}
                  onDelete={onDelete}
                  onViewCve={onViewCve}
                />
              ))}
            </ul>
          ) : (
            <div>
              {Array.from(groupedAlerts.entries()).map(([groupKey, groupAlerts]) => (
                <div key={groupKey} className="border-b last:border-b-0" style={{ borderColor: 'var(--cyber-border)' }}>
                  {/* Group Header */}
                  <button
                    onClick={() => toggleGroup(groupKey)}
                    className="w-full flex items-center gap-3 px-6 py-3 hover:bg-cyan-500/5 transition-colors"
                  >
                    {collapsedGroups.has(groupKey) ? (
                      <ChevronRight className="h-4 w-4 text-gray-500" strokeWidth={1.5} />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-gray-500" strokeWidth={1.5} />
                    )}
                    <span className="text-sm text-gray-300 mono font-medium">
                      {groupingMode === 'date' ? formatGroupDate(groupKey) : groupKey}
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-gray-700 text-gray-400 mono">
                      {groupAlerts.length}
                    </span>
                    {groupAlerts.filter(a => !a.read).length > 0 && (
                      <span className="px-2 py-0.5 rounded-full text-xs bg-red-500/20 text-red-400 mono">
                        {groupAlerts.filter(a => !a.read).length} NEW
                      </span>
                    )}
                  </button>

                  {/* Group Content */}
                  {!collapsedGroups.has(groupKey) && (
                    <ul className="divide-y" style={{ borderColor: 'var(--cyber-border)' }}>
                      {groupAlerts.map((alert) => (
                        <AlertRow
                          key={alert.id}
                          alert={alert}
                          isSelected={selectedIds.has(alert.id)}
                          onToggleSelect={toggleSelect}
                          onMarkRead={onMarkRead}
                          onDelete={onDelete}
                          onViewCve={onViewCve}
                        />
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="rounded-lg border p-20 text-center" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)'
        }}>
          <div className="w-20 h-20 mx-auto rounded-lg border-2 border-gray-700 flex items-center justify-center mb-6">
            <Bell className="h-10 w-10 text-gray-600" strokeWidth={1.5} />
          </div>
          <h3 className="text-lg font-semibold text-gray-100 mono mb-2">ALL CLEAR</h3>
          <p className="text-sm text-gray-500 mono">No alerts at this time</p>
        </div>
      )}
    </div>
  );
};

// Helper to format date group headers
const formatGroupDate = (dateStr: string): string => {
  const date = new Date(dateStr);
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);

  if (date.toDateString() === today.toDateString()) {
    return 'Today';
  } else if (date.toDateString() === yesterday.toDateString()) {
    return 'Yesterday';
  }

  return date.toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
};

// Alert Row Component
interface AlertRowProps {
  alert: Alert;
  isSelected: boolean;
  onToggleSelect: (id: string) => void;
  onMarkRead: (id: string) => void;
  onDelete: (id: string) => void;
  onViewCve?: (id: string) => void;
}

const AlertRow: React.FC<AlertRowProps> = ({
  alert,
  isSelected,
  onToggleSelect,
  onMarkRead,
  onDelete,
  onViewCve
}) => {
  return (
    <li
      className={`group p-6 transition-all hover:bg-cyan-500/5 ${
        !alert.read ? 'bg-cyan-500/5 border-l-4 border-l-cyan-500' : ''
      } ${isSelected ? 'bg-cyan-500/10' : ''}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-4 flex-1">
          {/* Checkbox */}
          <button
            onClick={() => onToggleSelect(alert.id)}
            className="mt-1 p-0.5 rounded hover:bg-cyan-500/10 transition-colors"
          >
            {isSelected ? (
              <CheckSquare className="h-5 w-5 text-cyan-400" strokeWidth={1.5} />
            ) : (
              <Square className="h-5 w-5 text-gray-500 group-hover:text-gray-400" strokeWidth={1.5} />
            )}
          </button>

          {/* Icon */}
          <div
            className={`mt-1 p-2.5 rounded-lg ${
              alert.type === 'NEW_MATCH'
                ? 'bg-red-500/20 border border-red-500/30'
                : 'bg-orange-500/20 border border-orange-500/30'
            }`}
          >
            <AlertCircle
              className={`h-4 w-4 ${
                alert.type === 'NEW_MATCH' ? 'text-red-400' : 'text-orange-400'
              }`}
              strokeWidth={1.5}
            />
          </div>

          {/* Content */}
          <div className="flex-1">
            <div className="flex items-center flex-wrap gap-3 mb-2">
              <button
                onClick={() => onViewCve && onViewCve(alert.cveId)}
                className="text-sm font-bold text-cyan-400 hover:text-cyan-300 mono transition-colors"
              >
                {alert.cveId}
              </button>
              <span className="w-1 h-1 bg-gray-600 rounded-full" />
              <span className="text-sm text-gray-400 mono">
                Watchlist: <span className="text-gray-300 font-medium">{alert.watchlistName}</span>
              </span>
            </div>
            <p className="text-sm text-gray-300 font-medium mb-2">
              {alert.type === 'NEW_MATCH' ? 'New CVE match' : 'CVE data updated'}
            </p>
            <div className="flex items-center text-xs text-gray-500 mono">
              <Calendar className="mr-1.5 h-3.5 w-3.5 text-gray-600" strokeWidth={1.5} />
              {new Date(alert.createdAt).toLocaleString('en-US', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false
              })}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center space-x-2 ml-4">
          {!alert.read && (
            <button
              onClick={() => onMarkRead(alert.id)}
              className="p-2.5 rounded-lg border transition-all hover:border-cyan-500 hover:bg-cyan-500/10"
              style={{ borderColor: 'var(--cyber-border)' }}
              title="Mark as read"
            >
              <Check className="h-4 w-4 text-cyan-400" strokeWidth={1.5} />
            </button>
          )}
          <button
            onClick={() => onDelete(alert.id)}
            className="p-2.5 rounded-lg border transition-all hover:border-red-500 hover:bg-red-500/10"
            style={{ borderColor: 'var(--cyber-border)' }}
            title="Delete alert"
          >
            <Trash2 className="h-4 w-4 text-gray-400 hover:text-red-400 transition-colors" strokeWidth={1.5} />
          </button>
        </div>
      </div>
    </li>
  );
};

export default Alerts;
