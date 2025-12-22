import React from 'react';
import { RefreshCw, CheckCircle, XCircle, Clock } from 'lucide-react';
import { JobRun } from '../types';

interface JobsProps {
  jobs: JobRun[];
  onRunIngest: () => void;
}

const Jobs: React.FC<JobsProps> = ({ jobs, onRunIngest }) => {
  // Determine if a job is running based on the latest job status
  const isRunning = jobs.length > 0 && jobs[0].status === 'RUNNING';

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800"><CheckCircle className="w-3 h-3 mr-1"/> Completed</span>;
      case 'FAILED':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800"><XCircle className="w-3 h-3 mr-1"/> Failed</span>;
      case 'RUNNING':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"><RefreshCw className="w-3 h-3 mr-1 animate-spin"/> Running</span>;
      default:
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">{status}</span>;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Ingestion Jobs</h1>
        <button
          onClick={onRunIngest}
          disabled={isRunning}
          className={`inline-flex items-center px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition shadow-sm text-sm font-medium ${isRunning ? 'opacity-75 cursor-not-allowed' : ''}`}
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${isRunning ? 'animate-spin' : ''}`} />
          {isRunning ? 'Ingesting...' : 'Run Ingestion'}
        </button>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Job ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Start Time</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Duration</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Items Processed</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Message</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {jobs.map((job) => {
                const duration = job.endTime 
                    ? Math.round((new Date(job.endTime).getTime() - new Date(job.startTime).getTime()) / 1000) + 's' 
                    : '-';
                
                return (
                    <tr key={job.id} className="hover:bg-gray-50 transition">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">#{job.id}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{getStatusBadge(job.status)}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(job.startTime).toLocaleString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 flex items-center">
                             <Clock className="w-3 h-3 mr-1 text-gray-400" />
                             {duration}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{job.itemsProcessed}</td>
                        <td className="px-6 py-4 text-sm text-gray-500 max-w-xs truncate" title={job.error || ''}>
                            {job.error ? <span className="text-red-600">{job.error}</span> : 'Success'}
                        </td>
                    </tr>
                );
            })}
          </tbody>
        </table>
        {jobs.length === 0 && (
            <div className="text-center py-10 text-gray-500 text-sm">No job history available.</div>
        )}
      </div>
    </div>
  );
};

export default Jobs;