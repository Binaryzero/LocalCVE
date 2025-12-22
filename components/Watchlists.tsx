import React from 'react';
import { Eye, Edit2, Trash2, Plus, ToggleLeft, ToggleRight } from 'lucide-react';
import { Watchlist } from '../types';

interface WatchlistsProps {
  watchlists: Watchlist[];
  onToggle: (id: string) => void;
  onDelete: (id: string) => void;
  onNavigate: (page: string) => void; // Used to go to create new via CVEs
}

const Watchlists: React.FC<WatchlistsProps> = ({ watchlists, onToggle, onDelete, onNavigate }) => {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Watchlists</h1>
        <button
          onClick={() => onNavigate('cves')}
          className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition shadow-sm text-sm font-medium"
        >
          <Plus className="h-4 w-4 mr-2" />
          New Watchlist
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {watchlists.map((wl) => (
          <div key={wl.id} className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden hover:shadow-md transition">
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <div className="flex items-center">
                  <div className={`p-2 rounded-lg ${wl.enabled ? 'bg-blue-100 text-blue-600' : 'bg-gray-100 text-gray-400'}`}>
                    <Eye className="h-5 w-5" />
                  </div>
                  <h3 className="ml-3 text-lg font-semibold text-gray-900">{wl.name}</h3>
                </div>
                <button onClick={() => onToggle(wl.id)} className="text-gray-400 hover:text-blue-600 transition">
                  {wl.enabled ? (
                    <ToggleRight className="h-8 w-8 text-green-500" />
                  ) : (
                    <ToggleLeft className="h-8 w-8 text-gray-300" />
                  )}
                </button>
              </div>

              <div className="space-y-2 mb-6">
                <div className="text-sm text-gray-600">
                  <span className="font-medium">Query:</span>
                  <pre className="mt-1 p-2 bg-gray-50 rounded border border-gray-100 text-xs overflow-x-auto">
                    {JSON.stringify(wl.query, null, 2)}
                  </pre>
                </div>
                <div className="flex justify-between text-sm text-gray-500 mt-2">
                   <span>Matches found:</span>
                   <span className="font-semibold text-gray-900">{wl.matchCount}</span>
                </div>
                <div className="flex justify-between text-sm text-gray-500">
                   <span>Last run:</span>
                   <span>{wl.lastRun ? new Date(wl.lastRun).toLocaleDateString() : 'Never'}</span>
                </div>
              </div>

              <div className="flex gap-2 pt-4 border-t border-gray-100">
                <button className="flex-1 inline-flex justify-center items-center px-3 py-2 border border-gray-200 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <Edit2 className="h-4 w-4 mr-2 text-gray-500" />
                  Edit
                </button>
                <button 
                  onClick={() => onDelete(wl.id)}
                  className="flex-1 inline-flex justify-center items-center px-3 py-2 border border-gray-200 shadow-sm text-sm font-medium rounded-md text-red-600 bg-white hover:bg-red-50"
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete
                </button>
              </div>
            </div>
          </div>
        ))}
        
        {watchlists.length === 0 && (
          <div className="col-span-full text-center py-12 bg-white rounded-xl border border-dashed border-gray-300">
            <Eye className="mx-auto h-12 w-12 text-gray-300" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No watchlists</h3>
            <p className="mt-1 text-sm text-gray-500">Get started by creating a new watchlist from the CVEs page.</p>
            <div className="mt-6">
              <button
                onClick={() => onNavigate('cves')}
                className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
              >
                <Plus className="-ml-1 mr-2 h-5 w-5" aria-hidden="true" />
                New Watchlist
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Watchlists;
