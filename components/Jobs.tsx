import React, { useState, useEffect, useRef } from 'react';
import { RefreshCw, CheckCircle, XCircle, Clock, Terminal, StopCircle, ChevronDown, ChevronRight, Plus, RefreshCcw, Equal, AlertTriangle } from 'lucide-react';
import { JobRun, JobLog } from '../types';

interface JobsProps {
  jobs: JobRun[];
  onRunIngest: () => void;
}

interface StatusConfig {
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>;
  bg: string;
  text: string;
  border: string;
  label: string;
  animate?: boolean;
}

const Jobs: React.FC<JobsProps> = ({ jobs, onRunIngest }) => {
  const isRunning = jobs.length > 0 && jobs[0].status === 'RUNNING';
  const [expandedJob, setExpandedJob] = useState<number | null>(null);
  const [jobLogs, setJobLogs] = useState<Map<number, JobLog[]>>(new Map());
  const [cancellingJobs, setCancellingJobs] = useState<Set<number>>(new Set());
  const eventSourceRef = useRef<EventSource | null>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // SSE connection for log streaming
  useEffect(() => {
    if (expandedJob !== null) {
      // Close existing connection
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      // Open new SSE connection
      const es = new EventSource(`/api/jobs/${expandedJob}/logs/stream`);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        const log: JobLog = JSON.parse(event.data);
        setJobLogs(prev => {
          const newMap = new Map(prev);
          const existing = newMap.get(expandedJob) || [];
          // Avoid duplicates
          if (!existing.find(l => l.id === log.id)) {
            newMap.set(expandedJob, [...existing, log]);
          }
          return newMap;
        });
      };

      es.onerror = () => {
        es.close();
      };

      return () => {
        es.close();
      };
    }
  }, [expandedJob]);

  // Auto-scroll logs
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [jobLogs, expandedJob]);

  const handleCancel = async (jobId: number) => {
    setCancellingJobs(prev => new Set(prev).add(jobId));
    try {
      await fetch(`/api/jobs/${jobId}/cancel`, { method: 'POST' });
    } catch (err) {
      console.error('Failed to cancel job:', err);
    }
  };

  const toggleJobLogs = (jobId: number) => {
    if (expandedJob === jobId) {
      setExpandedJob(null);
    } else {
      setExpandedJob(jobId);
    }
  };

  const getStatusBadge = (status: string) => {
    const configs: Record<string, StatusConfig> = {
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
      },
      'CANCELLED': {
        icon: StopCircle,
        bg: 'bg-yellow-500/20',
        text: 'text-yellow-400',
        border: 'border-yellow-500/30',
        label: 'CANCELLED'
      }
    };

    const config = configs[status] || {
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

  const getLogLevelColor = (level: string) => {
    switch (level) {
      case 'ERROR': return 'text-red-400';
      case 'WARN': return 'text-yellow-400';
      default: return 'text-gray-400';
    }
  };

  const formatPhase = (phase: string | null) => {
    if (!phase) return '';
    return phase.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
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
                <th className="px-4 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30 w-8"></th>
                <th className="px-4 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  JOB ID
                </th>
                <th className="px-4 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  STATUS
                </th>
                <th className="px-4 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  PROGRESS
                </th>
                <th className="px-4 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  CHANGES
                </th>
                <th className="px-4 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  DURATION
                </th>
                <th className="px-4 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider mono bg-gray-900/30">
                  ACTIONS
                </th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job, index) => {
                const duration = job.endTime
                  ? Math.round((new Date(job.endTime).getTime() - new Date(job.startTime).getTime()) / 1000) + 's'
                  : job.status === 'RUNNING'
                    ? Math.round((Date.now() - new Date(job.startTime).getTime()) / 1000) + 's'
                    : '-';

                const isExpanded = expandedJob === job.id;
                const logs = jobLogs.get(job.id) || [];
                const isCancelling = cancellingJobs.has(job.id);

                return (
                  <React.Fragment key={job.id}>
                    <tr
                      className="hover:bg-cyan-500/5 transition-all cursor-pointer"
                      style={{
                        borderBottom: isExpanded ? 'none' : (index < jobs.length - 1 ? '1px solid var(--cyber-border)' : 'none')
                      }}
                      onClick={() => toggleJobLogs(job.id)}
                    >
                      <td className="px-4 py-4 whitespace-nowrap">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 text-gray-500" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-gray-500" />
                        )}
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap text-sm font-bold text-cyan-400 mono">
                        #{job.id}
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap">
                        {getStatusBadge(job.status)}
                        {job.currentPhase && job.status === 'RUNNING' && (
                          <span className="ml-2 text-xs text-gray-500 mono">{formatPhase(job.currentPhase)}</span>
                        )}
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap">
                        <div className="flex flex-col gap-1">
                          {job.status === 'RUNNING' && job.totalFiles ? (
                            <>
                              <div className="w-32 bg-gray-700 rounded-full h-2">
                                <div
                                  className="bg-cyan-500 h-2 rounded-full transition-all duration-500"
                                  style={{ width: `${job.progressPercent}%` }}
                                />
                              </div>
                              <span className="text-xs text-gray-500 mono">
                                {job.itemsProcessed.toLocaleString()} / {job.totalFiles.toLocaleString()} ({job.progressPercent}%)
                              </span>
                            </>
                          ) : (
                            <span className="text-sm text-gray-400 mono">
                              {job.itemsProcessed.toLocaleString()} items
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-3 text-xs mono">
                          <span className="flex items-center text-green-400" title="Added">
                            <Plus className="w-3 h-3 mr-0.5" />{job.itemsAdded || 0}
                          </span>
                          <span className="flex items-center text-yellow-400" title="Updated">
                            <RefreshCcw className="w-3 h-3 mr-0.5" />{job.itemsUpdated || 0}
                          </span>
                          <span className="flex items-center text-gray-500" title="Unchanged">
                            <Equal className="w-3 h-3 mr-0.5" />{job.itemsUnchanged || 0}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap">
                        <div className="flex items-center text-sm text-gray-400 mono">
                          <Clock className="w-3.5 h-3.5 mr-1.5 text-gray-500" strokeWidth={1.5} />
                          {duration}
                        </div>
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap" onClick={e => e.stopPropagation()}>
                        {job.status === 'RUNNING' && !isCancelling && (
                          <button
                            onClick={() => handleCancel(job.id)}
                            className="inline-flex items-center px-2.5 py-1 rounded border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors text-xs mono"
                          >
                            <StopCircle className="w-3 h-3 mr-1" />
                            CANCEL
                          </button>
                        )}
                        {isCancelling && (
                          <span className="text-xs text-yellow-400 mono">Cancelling...</span>
                        )}
                        {job.error && (
                          <span className="text-red-400 mono text-xs truncate max-w-[150px] block" title={job.error}>
                            {job.error}
                          </span>
                        )}
                      </td>
                    </tr>

                    {/* Expanded Log Panel */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={7} className="p-0" style={{ borderBottom: index < jobs.length - 1 ? '1px solid var(--cyber-border)' : 'none' }}>
                          <div className="bg-gray-900/50 border-t border-gray-800">
                            <div className="px-4 py-2 border-b border-gray-800 flex justify-between items-center">
                              <span className="text-xs font-semibold text-gray-500 uppercase mono">Job Logs</span>
                              <span className="text-xs text-gray-600 mono">{logs.length} entries</span>
                            </div>
                            <div
                              ref={logContainerRef}
                              className="max-h-64 overflow-y-auto p-3 font-mono text-xs"
                              style={{ background: 'rgba(0,0,0,0.3)' }}
                            >
                              {logs.length === 0 ? (
                                <div className="text-gray-600 text-center py-4">No logs available</div>
                              ) : (
                                logs.map((log) => (
                                  <div key={log.id} className="flex gap-2 py-0.5 hover:bg-gray-800/30">
                                    <span className="text-gray-600 flex-shrink-0">
                                      {new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                                    </span>
                                    <span className={`flex-shrink-0 w-12 ${getLogLevelColor(log.level)}`}>
                                      {log.level === 'ERROR' && <AlertTriangle className="w-3 h-3 inline mr-1" />}
                                      [{log.level}]
                                    </span>
                                    <span className="text-gray-300">{log.message}</span>
                                    {log.metadata && (
                                      <span className="text-gray-600 truncate" title={JSON.stringify(log.metadata)}>
                                        {JSON.stringify(log.metadata)}
                                      </span>
                                    )}
                                  </div>
                                ))
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
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
