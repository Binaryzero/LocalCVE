import React, { useState, useEffect } from 'react';
import { Search, Filter, Save, ExternalLink } from 'lucide-react';
import { Cve, QueryModel } from '../types';

interface CveListProps {
  cves: Cve[];
  onSaveWatchlist: (query: QueryModel) => void;
}

const CveList: React.FC<CveListProps> = ({ cves, onSaveWatchlist }) => {
  const [filters, setFilters] = useState<QueryModel>({
    text: '',
    cvss_min: 0,
    cvss_max: 10,
    kev: false,
  });
  const [showFilters, setShowFilters] = useState(false);
  const [filteredCves, setFilteredCves] = useState<Cve[]>(cves);

  useEffect(() => {
    // Client-side filtering simulation (in a real app, this would be server-side)
    const result = cves.filter(cve => {
      const matchText = !filters.text || 
        cve.id.toLowerCase().includes(filters.text.toLowerCase()) || 
        cve.description.toLowerCase().includes(filters.text.toLowerCase());
      
      const matchScore = (cve.cvssV3Score || 0) >= (filters.cvss_min || 0) && 
                         (cve.cvssV3Score || 0) <= (filters.cvss_max || 10);
      
      const matchKev = !filters.kev || cve.kev;

      return matchText && matchScore && matchKev;
    });
    setFilteredCves(result);
  }, [filters, cves]);

  const handleInputChange = (field: keyof QueryModel, value: any) => {
    setFilters(prev => ({ ...prev, [field]: value }));
  };

  const getSeverityColor = (severity: string | null) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-100 text-red-800';
      case 'HIGH': return 'bg-orange-100 text-orange-800';
      case 'MEDIUM': return 'bg-yellow-100 text-yellow-800';
      case 'LOW': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h1 className="text-2xl font-bold text-gray-900">Vulnerabilities (CVEs)</h1>
        <button
          onClick={() => onSaveWatchlist(filters)}
          className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition shadow-sm text-sm font-medium"
        >
          <Save className="h-4 w-4 mr-2" />
          Save as Watchlist
        </button>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="p-4 border-b border-gray-200 bg-gray-50 rounded-t-xl">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search CVE ID or description..."
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                value={filters.text || ''}
                onChange={(e) => handleInputChange('text', e.target.value)}
              />
            </div>
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center px-4 py-2 border rounded-lg text-sm font-medium transition ${
                showFilters ? 'bg-blue-50 border-blue-200 text-blue-700' : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
              }`}
            >
              <Filter className="h-4 w-4 mr-2" />
              Filters
            </button>
          </div>

          {showFilters && (
            <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-white border border-gray-200 rounded-lg">
              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1">Min CVSS Score</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  className="w-full p-2 border border-gray-300 rounded-md text-sm"
                  value={filters.cvss_min}
                  onChange={(e) => handleInputChange('cvss_min', parseFloat(e.target.value) || 0)}
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1">Max CVSS Score</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  className="w-full p-2 border border-gray-300 rounded-md text-sm"
                  value={filters.cvss_max}
                  onChange={(e) => handleInputChange('cvss_max', parseFloat(e.target.value) || 10)}
                />
              </div>
              <div className="flex items-center pt-5">
                <input
                  type="checkbox"
                  id="kev-check"
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  checked={filters.kev || false}
                  onChange={(e) => handleInputChange('kev', e.target.checked)}
                />
                <label htmlFor="kev-check" className="ml-2 block text-sm text-gray-700">
                  Known Exploited (KEV) Only
                </label>
              </div>
            </div>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-40">CVE ID</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-32">Severity</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-32">Published</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-24">Refs</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredCves.length > 0 ? (
                filteredCves.map((cve) => (
                  <tr key={cve.id} className="hover:bg-gray-50 transition">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-blue-600">
                      {cve.id}
                      {cve.kev && (
                        <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
                          KEV
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getSeverityColor(cve.cvssV3Severity)}`}>
                        {cve.cvssV3Score?.toFixed(1) || 'N/A'} {cve.cvssV3Severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 line-clamp-2 max-w-lg">
                      {cve.description}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(cve.published).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                       {cve.references.length > 0 && (
                           <a href={cve.references[0]} target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-gray-600">
                               <ExternalLink className="h-4 w-4" />
                           </a>
                       )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-gray-500">
                    No CVEs found matching your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default CveList;
