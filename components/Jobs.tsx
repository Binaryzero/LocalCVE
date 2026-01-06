import React from 'react';
import { RefreshCw, CheckCircle, XCircle, Clock, Terminal } from 'lucide-react';
import { JobRun } from '../types';

interface JobsProps {
  jobs: JobRun[];
  onRunIngest: () => void;
}

const Jobs: React.FC<JobsProps> = ({ jobs, onRunIngest }) => {
  const isRunning = jobs.length > 0 && jobs[0].status === 'RUNNING';

  const getStatusBadge = (status: string) => {
    const configs = {
      'COMPLETED': {
        icon: CheckCircle,
        bg: 'bg-green-500/20',
        text: 'text-green-400',
        border: 'border-green-500/30',
        label: 'COMPLETED'
      },
      'FAILED': {
        icon: XCircle,
        bg: 'bg-red-500/20',
        text: 'text-red-400',
        border: 'border-red-500/30',
        label: 'FAILED'
      },
      'RUNNING': {
        icon: RefreshCw,
        bg: 'bg-cyan-500/20',
        text: 'text-cyan-400',
        border: 'border-cyan-500/30',
        label: 'RUNNING',
        animate: true
      }
    };

    const config = configs[status as keyof typeof configs] || {
      icon: Clock,
      bg: 'bg-gray-500/20',
      text: 'text-gray-400',
      border: 'border-gray-500/30',
      label: status
    };

    const Icon = config.icon;

    return (
      <div className={`inline-flex items-center px-2.5 py-1 rounded border ${config.bg} ${config.border}`}>
        <Icon className={`w-3.5 h-3.5 mr-1.5 ${config.text} ${config.animate ? 'animate-spin' : ''}`} strokeWidth={1.5} />
        <span className={`text-xs font-bold mono ${config.text}`}>{config.label}</span>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-100 mono tracking-tight">INGESTION CONTROL</h1>
          <p className="text-sm text-gray-500 mono mt-1">CVE data synchronization jobs</p>
        </div>
        <button
          onClick={onRunIngest}
          disabled={isRunning}
          className={`inline-flex items-center px-5 py-3 rounded-lg border transition-all ${
            isRunning
              ? 'opacity-50 cursor-not-allowed'
              : 'hover:border-cyan-500'
          }`}
          style={{
            background: isRunning ? 'rgba(6, 182, 212, 0.05)' : 'rgba(6, 182, 212, 0.1)',
            borderColor: 'var(--cyber-accent)',
            color: 'var(--cyber-accent)'
          }}
        >
          <Terminal className={`h-4 w-4 mr-2 ${isRunning ? 'animate-pulse' : ''}`} strokeWidth={1.5} />
          <span className="mono text-sm font-medium">
            {isRunning ? 'INGESTING...' : 'RUN INGESTION'}
          </span>
        </button>
      </div>

      {/* Jobs Table */}
      <div className="rounded-lg border overflow-hidden" style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--cyber-border)' }}>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  JOB ID
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  STATUS
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  START TIME
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  DURATION
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  PROCESSED
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  MESSAGE
                </th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job, index) => {
                const duration = job.endTime
                  ? Math.round((new Date(job.endTime).getTime() - new Date(job.startTime).getTime()) / 1000) + 's'
                  : '-';

                return (
                  <tr
                    key={job.id}
                    className="hover:bg-cyan-500/5 transition-all"
                    style={{
                      borderBottom: index < jobs.length - 1 ? '1px solid var(--cyber-border)' : 'none'
                    }}
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-bold text-cyan-400 mono">
                      #{job.id}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getStatusBadge(job.status)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400 mono">
                      {new Date(job.startTime).toLocaleString('en-US', {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false
                      })}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center text-sm text-gray-400 mono">
                        <Clock className="w-3.5 h-3.5 mr-1.5 text-gray-500" strokeWidth={1.5} />
                        {duration}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400 mono">
                      {job.itemsProcessed.toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-sm max-w-xs truncate" title={job.error || ''}>
                      {job.error ? (
                        <span className="text-red-400 mono">{job.error}</span>
                      ) : (
                        <span className="text-gray-500 mono">Success</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {jobs.length === 0 && (
          <div className="text-center py-16">
            <div className="w-16 h-16 mx-auto rounded-lg border border-gray-700 flex items-center justify-center mb-4">
              <Terminal className="h-8 w-8 text-gray-600" strokeWidth={1.5} />
            </div>
            <p className="text-gray-500 mono text-sm">NO JOB HISTORY AVAILABLE</p>
            <p className="text-gray-600 mono text-xs mt-2">Run your first ingestion to begin</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Jobs;
