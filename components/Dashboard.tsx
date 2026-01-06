import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { AlertTriangle, Shield, Activity, Search, ChevronRight, Zap } from 'lucide-react';
import { Cve, Alert } from '../types';

interface DashboardProps {
  cves: Cve[];
  alerts: Alert[];
  onNavigate: (page: string) => void;
  onViewCve: (id: string) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ cves, alerts, onNavigate, onViewCve }) => {
  const criticalCount = cves.filter(c => c.cvssV3Severity === 'CRITICAL').length;
  const highCount = cves.filter(c => c.cvssV3Severity === 'HIGH').length;
  const mediumCount = cves.filter(c => c.cvssV3Severity === 'MEDIUM').length;
  const lowCount = cves.filter(c => c.cvssV3Severity === 'LOW').length;

  const severityData = [
    { name: 'CRIT', count: criticalCount, color: '#ef4444' },
    { name: 'HIGH', count: highCount, color: '#f59e0b' },
    { name: 'MED', count: mediumCount, color: '#eab308' },
    { name: 'LOW', count: lowCount, color: '#10b981' },
  ];

  const unreadAlerts = alerts.filter(a => !a.read).length;
  const recentCves = cves.slice(0, 5);

  const StatCard = ({ icon: Icon, label, value, color, onClick }: any) => (
    <div
      onClick={onClick}
      className={`group relative overflow-hidden rounded-lg border p-6 ${onClick ? 'cursor-pointer' : ''}`}
      style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}
    >
      {/* Animated border on hover */}
      <div className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none`}
        style={{
          background: `linear-gradient(135deg, ${color}15, transparent)`,
        }}
      />

      <div className="relative z-10 flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-gray-400 mono uppercase tracking-wider mb-3">{label}</p>
          <p className="text-4xl font-bold mono" style={{ color }}>{value}</p>
        </div>
        <div className="p-3 rounded-lg transition-all duration-300 group-hover:scale-110"
          style={{ background: `${color}20` }}
        >
          <Icon className="h-6 w-6" style={{ color }} strokeWidth={1.5} />
        </div>
      </div>

      {/* Glow effect */}
      <div className="absolute -bottom-2 -right-2 w-24 h-24 rounded-full opacity-0 group-hover:opacity-20 transition-opacity duration-300 blur-2xl"
        style={{ background: color }}
      />
    </div>
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100 mono tracking-tight">THREAT OVERVIEW</h1>
          <p className="text-sm text-gray-500 mono mt-1">Real-time vulnerability intelligence</p>
        </div>
        <div className="flex items-center space-x-2 px-4 py-2 rounded-lg border" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)'
        }}>
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
          <span className="text-sm text-gray-400 mono">MONITORING</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          icon={AlertTriangle}
          label="Critical Threats"
          value={criticalCount}
          color="#ef4444"
        />
        <StatCard
          icon={Activity}
          label="Active Alerts"
          value={unreadAlerts}
          color="#06b6d4"
          onClick={() => onNavigate('alerts')}
        />
        <StatCard
          icon={Shield}
          label="Total CVEs"
          value={cves.length}
          color="#10b981"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Chart */}
        <div className="lg:col-span-2 rounded-lg border p-6" style={{
          background: 'var(--cyber-surface)',
          borderColor: 'var(--cyber-border)'
        }}>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-gray-100 mono">SEVERITY DISTRIBUTION</h2>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
              <span className="text-xs text-gray-500 mono">LIVE</span>
            </div>
          </div>

          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis
                  dataKey="name"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#9ca3af', fontFamily: 'JetBrains Mono', fontSize: 12 }}
                />
                <YAxis
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#9ca3af', fontFamily: 'JetBrains Mono', fontSize: 12 }}
                  width={40}
                />
                <Tooltip
                  contentStyle={{
                    background: '#111827',
                    border: '1px solid #1f2937',
                    borderRadius: '8px',
                    fontFamily: 'JetBrains Mono',
                    fontSize: '12px'
                  }}
                  labelStyle={{ color: '#06b6d4' }}
                  itemStyle={{ color: '#f3f4f6' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Quick Actions */}
          <div className="rounded-lg border p-6" style={{
            background: 'var(--cyber-surface)',
            borderColor: 'var(--cyber-border)'
          }}>
            <h2 className="text-lg font-semibold text-gray-100 mono mb-4">QUICK ACCESS</h2>
            <div className="space-y-3">
              <button
                onClick={() => onNavigate('cves')}
                className="group w-full flex items-center justify-between p-4 rounded-lg border transition-all hover:border-cyan-500/50"
                style={{
                  background: 'rgba(6, 182, 212, 0.05)',
                  borderColor: 'var(--cyber-border)'
                }}
              >
                <span className="flex items-center text-gray-300 mono text-sm">
                  <Search className="h-4 w-4 mr-3 text-cyan-400" strokeWidth={1.5} />
                  Search Threats
                </span>
                <ChevronRight className="h-4 w-4 text-gray-600 group-hover:text-cyan-400 transition-colors" />
              </button>

              <button
                onClick={() => onNavigate('jobs')}
                className="group w-full flex items-center justify-between p-4 rounded-lg border transition-all hover:border-cyan-500/50"
                style={{
                  background: 'rgba(6, 182, 212, 0.05)',
                  borderColor: 'var(--cyber-border)'
                }}
              >
                <span className="flex items-center text-gray-300 mono text-sm">
                  <Zap className="h-4 w-4 mr-3 text-cyan-400" strokeWidth={1.5} />
                  Run Ingestion
                </span>
                <ChevronRight className="h-4 w-4 text-gray-600 group-hover:text-cyan-400 transition-colors" />
              </button>
            </div>
          </div>

          {/* Recent CVEs */}
          <div className="rounded-lg border p-6" style={{
            background: 'var(--cyber-surface)',
            borderColor: 'var(--cyber-border)'
          }}>
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-semibold text-gray-100 mono">RECENT</h2>
              <button
                onClick={() => onNavigate('cves')}
                className="text-xs text-cyan-400 hover:text-cyan-300 mono transition-colors"
              >
                VIEW ALL →
              </button>
            </div>

            <div className="space-y-3">
              {recentCves.map(cve => (
                <div
                  key={cve.id}
                  className="group p-3 border rounded-lg cursor-pointer transition-all hover:border-cyan-500/50"
                  style={{ borderColor: 'var(--cyber-border)' }}
                  onClick={() => onViewCve(cve.id)}
                >
                  <div className="flex items-start justify-between mb-2">
                    <p className="text-sm font-bold text-cyan-400 mono">{cve.id}</p>
                    {cve.cvssV3Severity && (
                      <span className={`text-xs px-2 py-0.5 rounded mono ${
                        cve.cvssV3Severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                        cve.cvssV3Severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                        cve.cvssV3Severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        {cve.cvssV3Score?.toFixed(1)}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-gray-400 line-clamp-2 leading-relaxed">{cve.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
