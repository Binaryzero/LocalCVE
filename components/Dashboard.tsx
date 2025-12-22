import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { AlertTriangle, CheckCircle, Activity, Search } from 'lucide-react';
import { Cve, Alert } from '../types';

interface DashboardProps {
  cves: Cve[];
  alerts: Alert[];
  onNavigate: (page: string) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ cves, alerts, onNavigate }) => {
  const criticalCount = cves.filter(c => c.cvssV3Severity === 'CRITICAL').length;
  const highCount = cves.filter(c => c.cvssV3Severity === 'HIGH').length;
  const mediumCount = cves.filter(c => c.cvssV3Severity === 'MEDIUM').length;
  const lowCount = cves.filter(c => c.cvssV3Severity === 'LOW').length;

  const severityData = [
    { name: 'Critical', count: criticalCount },
    { name: 'High', count: highCount },
    { name: 'Medium', count: mediumCount },
    { name: 'Low', count: lowCount },
  ];

  const unreadAlerts = alerts.filter(a => !a.read).length;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-start space-x-4">
          <div className="p-3 bg-red-100 rounded-lg">
            <AlertTriangle className="h-6 w-6 text-red-600" />
          </div>
          <div>
            <p className="text-sm font-medium text-gray-500">Critical Vulnerabilities</p>
            <p className="text-2xl font-bold text-gray-900">{criticalCount}</p>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-start space-x-4 cursor-pointer hover:bg-gray-50 transition" onClick={() => onNavigate('alerts')}>
          <div className="p-3 bg-blue-100 rounded-lg">
            <Activity className="h-6 w-6 text-blue-600" />
          </div>
          <div>
            <p className="text-sm font-medium text-gray-500">Unread Alerts</p>
            <p className="text-2xl font-bold text-gray-900">{unreadAlerts}</p>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-start space-x-4">
          <div className="p-3 bg-green-100 rounded-lg">
            <CheckCircle className="h-6 w-6 text-green-600" />
          </div>
          <div>
            <p className="text-sm font-medium text-gray-500">System Status</p>
            <p className="text-lg font-bold text-gray-900">Operational</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Vulnerability Severity Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <XAxis dataKey="name" axisLine={false} tickLine={false} />
                <YAxis axisLine={false} tickLine={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#4F46E5" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
            <div className="space-y-4">
                <button onClick={() => onNavigate('cves')} className="w-full flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition">
                    <span className="flex items-center text-gray-700">
                        <Search className="h-5 w-5 mr-3 text-gray-500" />
                        Search CVEs
                    </span>
                    <span className="text-gray-400">→</span>
                </button>
                <button onClick={() => onNavigate('jobs')} className="w-full flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition">
                    <span className="flex items-center text-gray-700">
                        <Activity className="h-5 w-5 mr-3 text-gray-500" />
                        View Ingestion Jobs
                    </span>
                    <span className="text-gray-400">→</span>
                </button>
            </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
