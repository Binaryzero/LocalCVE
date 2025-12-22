import React from 'react';
import { Bell, Check, Trash2, Calendar } from 'lucide-react';
import { Alert } from '../types';

interface AlertsProps {
  alerts: Alert[];
  onMarkRead: (id: string) => void;
  onDelete: (id: string) => void;
}

const Alerts: React.FC<AlertsProps> = ({ alerts, onMarkRead, onDelete }) => {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Alert Inbox</h1>
        <div className="text-sm text-gray-500">
            {alerts.filter(a => !a.read).length} unread alerts
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {alerts.length > 0 ? (
          <ul className="divide-y divide-gray-200">
            {alerts.map((alert) => (
              <li 
                key={alert.id} 
                className={`p-6 hover:bg-gray-50 transition ${!alert.read ? 'bg-blue-50/50' : ''}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4">
                    <div className={`mt-1 p-2 rounded-full ${alert.type === 'NEW_MATCH' ? 'bg-red-100 text-red-600' : 'bg-orange-100 text-orange-600'}`}>
                      <Bell className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="flex items-center">
                          <span className="text-sm font-medium text-blue-600 hover:underline cursor-pointer">{alert.cveId}</span>
                          <span className="mx-2 text-gray-300">•</span>
                          <span className="text-sm text-gray-500">
                             Matched watchlist: <span className="font-medium text-gray-900">{alert.watchlistName}</span>
                          </span>
                      </div>
                      <p className="mt-1 text-sm text-gray-900 font-medium">
                        {alert.type === 'NEW_MATCH' ? 'New vulnerability detected' : 'Vulnerability updated'}
                      </p>
                      <div className="mt-2 flex items-center text-xs text-gray-500">
                        <Calendar className="mr-1.5 h-3 w-3 flex-shrink-0 text-gray-400" />
                        {new Date(alert.createdAt).toLocaleString()}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {!alert.read && (
                        <button 
                            onClick={() => onMarkRead(alert.id)}
                            className="p-2 text-blue-600 hover:bg-blue-100 rounded-full"
                            title="Mark as read"
                        >
                            <Check className="h-4 w-4" />
                        </button>
                    )}
                    <button 
                        onClick={() => onDelete(alert.id)}
                        className="p-2 text-gray-400 hover:bg-gray-100 hover:text-red-500 rounded-full"
                        title="Delete alert"
                    >
                        <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-center py-16">
            <Bell className="mx-auto h-12 w-12 text-gray-300" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No alerts</h3>
            <p className="mt-1 text-sm text-gray-500">You're all caught up!</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Alerts;
