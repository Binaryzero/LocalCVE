import React from 'react';
import { Bell, Check, Trash2, Calendar, AlertCircle } from 'lucide-react';
import { Alert } from '../types';

interface AlertsProps {
  alerts: Alert[];
  onMarkRead: (id: string) => void;
  onDelete: (id: string) => void;
  onViewCve?: (id: string) => void;
}

const Alerts: React.FC<AlertsProps> = ({ alerts, onMarkRead, onDelete, onViewCve }) => {
  const unreadCount = alerts.filter(a => !a.read).length;

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
          </div>
        </div>

        {unreadCount > 0 && (
          <div className="flex items-center space-x-2 px-4 py-2 rounded-lg border animate-pulse"
            style={{
              background: 'rgba(239, 68, 68, 0.1)',
              borderColor: '#ef4444'
            }}
          >
            <div className="w-2 h-2 bg-red-400 rounded-full" />
            <span className="text-sm text-red-400 mono font-medium">{unreadCount} NEW ALERTS</span>
          </div>
        )}
      </div>

      {/* Alerts List */}
      {alerts.length > 0 ? (
        <div className="rounded-lg border overflow-hidden" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)'
        }}>
          <ul className="divide-y" style={{ borderColor: 'var(--cyber-border)' }}>
            {alerts.map((alert) => (
              <li
                key={alert.id}
                className={`group p-6 transition-all hover:bg-cyan-500/5 ${
                  !alert.read ? 'bg-cyan-500/5 border-l-4 border-l-cyan-500' : ''
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
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
                        {alert.type === 'NEW_MATCH' ? 'New vulnerability detected' : 'Vulnerability updated'}
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
            ))}
          </ul>
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

export default Alerts;
