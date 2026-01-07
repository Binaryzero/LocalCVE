import React, { useState, useEffect } from 'react';
import { ArrowLeft, ExternalLink, Shield, Calendar, Clock, Database, Copy, Check } from 'lucide-react';
import CvssVersionTabs from './CvssVersionTabs';

interface CveDetailProps {
    id: string;
    onBack: () => void;
}

const CveDetail: React.FC<CveDetailProps> = ({ id, onBack }) => {
    const [data, setData] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [copiedJson, setCopiedJson] = useState(false);

    useEffect(() => {
        fetch(`/api/cves/${id}`)
            .then(res => res.json())
            .then(json => {
                setData(json);
                setLoading(false);
            })
            .catch(err => {
                console.error('Failed to fetch CVE details:', err);
                setLoading(false);
            });
    }, [id]);

    const copyJson = () => {
        navigator.clipboard.writeText(JSON.stringify(data, null, 2));
        setCopiedJson(true);
        setTimeout(() => setCopiedJson(false), 2000);
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center py-20">
                <div className="w-16 h-16 border-4 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
                <p className="mt-4 text-gray-400 mono text-sm">LOADING {id}...</p>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="flex flex-col items-center justify-center py-20">
                <div className="w-16 h-16 rounded-lg border-2 border-red-500/30 flex items-center justify-center">
                    <Shield className="h-8 w-8 text-red-500" strokeWidth={1.5} />
                </div>
                <p className="mt-4 text-red-400 mono text-sm">CVE {id} NOT FOUND</p>
            </div>
        );
    }

    const getSeverityColor = (severity: string) => {
        const colors: Record<string, string> = {
            'CRITICAL': '#ef4444',
            'HIGH': '#f59e0b',
            'MEDIUM': '#eab308',
            'LOW': '#10b981'
        };
        return colors[severity] || '#6b7280';
    };

    return (
        <div className="space-y-6">
            {/* Back Button */}
            <button
                onClick={onBack}
                className="inline-flex items-center text-cyan-400 hover:text-cyan-300 transition-colors mono text-sm font-medium"
            >
                <ArrowLeft className="h-4 w-4 mr-2" strokeWidth={1.5} />
                BACK TO LIST
            </button>

            {/* Main Card */}
            <div className="rounded-lg border overflow-hidden" style={{
                background: 'var(--cyber-surface)',
                borderColor: 'var(--cyber-border)'
            }}>
                {/* Header */}
                <div className="p-8 border-b" style={{
                    borderColor: 'var(--cyber-border)',
                    background: 'rgba(6, 182, 212, 0.03)'
                }}>
                    <div className="flex flex-col lg:flex-row justify-between lg:items-start gap-6">
                        <div className="flex-1">
                            <h1 className="text-4xl font-bold text-gray-100 mono tracking-tight mb-4">{id}</h1>
                            <div className="flex flex-wrap gap-3">
                                <span className="inline-flex items-center px-3 py-1.5 rounded-lg border text-sm mono font-medium"
                                    style={{
                                        background: 'rgba(6, 182, 212, 0.1)',
                                        borderColor: 'var(--cyber-accent)',
                                        color: 'var(--cyber-accent)'
                                    }}
                                >
                                    <Database className="h-3.5 w-3.5 mr-2" strokeWidth={1.5} />
                                    {data.vulnStatus || 'PUBLISHED'}
                                </span>
                                {data.score && (
                                    <span className="inline-flex items-center px-3 py-1.5 rounded-lg border text-sm mono font-bold"
                                        style={{
                                            background: `${getSeverityColor(data.severity)}20`,
                                            borderColor: `${getSeverityColor(data.severity)}40`,
                                            color: getSeverityColor(data.severity)
                                        }}
                                    >
                                        <Shield className="h-3.5 w-3.5 mr-2" strokeWidth={1.5} />
                                        CVSS {data.score} • {data.severity}
                                    </span>
                                )}
                            </div>
                        </div>

                        <div className="flex flex-col gap-3 text-sm text-gray-400 mono">
                            <div className="flex items-center">
                                <Calendar className="h-4 w-4 mr-2 text-gray-500" strokeWidth={1.5} />
                                <span className="text-gray-500">Published:</span>
                                <span className="ml-2 text-gray-300">{new Date(data.published).toLocaleDateString()}</span>
                            </div>
                            <div className="flex items-center">
                                <Clock className="h-4 w-4 mr-2 text-gray-500" strokeWidth={1.5} />
                                <span className="text-gray-500">Updated:</span>
                                <span className="ml-2 text-gray-300">{new Date(data.lastModified).toLocaleDateString()}</span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Content */}
                <div className="p-8 space-y-8">
                    {/* CVSS Scores - Multi-Version Display */}
                    <section>
                        <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                            <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                            VULNERABILITY SEVERITY
                        </h2>
                        <CvssVersionTabs
                            metrics={data.metrics || []}
                            cvss2Score={data.cvss2Score}
                            cvss2Severity={data.cvss2Severity}
                            cvss30Score={data.cvss30Score}
                            cvss30Severity={data.cvss30Severity}
                            cvss31Score={data.cvss31Score}
                            cvss31Severity={data.cvss31Severity}
                        />
                    </section>

                    {/* Description */}
                    <section>
                        <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                            <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                            DESCRIPTION
                        </h2>
                        <p className="text-gray-300 leading-relaxed text-base pl-4">
                            {data.description}
                        </p>
                    </section>

                    {/* References */}
                    {data.references && data.references.length > 0 && (
                        <section>
                            <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                REFERENCES ({data.references.length})
                            </h2>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pl-4">
                                {data.references.map((ref: string, i: number) => (
                                    <a
                                        key={i}
                                        href={ref}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="group flex items-center justify-between p-4 border rounded-lg transition-all hover:border-cyan-500/50"
                                        style={{
                                            background: 'rgba(6, 182, 212, 0.03)',
                                            borderColor: 'var(--cyber-border)'
                                        }}
                                    >
                                        <span className="text-sm text-cyan-400 truncate mr-3 group-hover:text-cyan-300 transition-colors">
                                            {ref.replace(/^https?:\/\//, '')}
                                        </span>
                                        <ExternalLink className="h-4 w-4 flex-shrink-0 text-gray-500 group-hover:text-cyan-400 transition-colors" strokeWidth={1.5} />
                                    </a>
                                ))}
                            </div>
                        </section>
                    )}

                    {/* Raw JSON */}
                    <section>
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-lg font-semibold text-gray-100 mono flex items-center">
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                RAW DATA
                            </h2>
                            <button
                                onClick={copyJson}
                                className="inline-flex items-center px-3 py-1.5 rounded-lg border text-xs mono font-medium transition-all hover:border-cyan-500"
                                style={{
                                    background: 'rgba(6, 182, 212, 0.05)',
                                    borderColor: 'var(--cyber-border)',
                                    color: copiedJson ? '#10b981' : 'var(--cyber-accent)'
                                }}
                            >
                                {copiedJson ? (
                                    <>
                                        <Check className="h-3.5 w-3.5 mr-1.5" strokeWidth={1.5} />
                                        COPIED
                                    </>
                                ) : (
                                    <>
                                        <Copy className="h-3.5 w-3.5 mr-1.5" strokeWidth={1.5} />
                                        COPY JSON
                                    </>
                                )}
                            </button>
                        </div>
                        <div className="rounded-lg border p-6 overflow-auto max-h-96" style={{
                            background: '#000000',
                            borderColor: 'var(--cyber-border)'
                        }}>
                            <pre className="text-green-400 text-xs leading-relaxed mono">
                                {JSON.stringify(data, null, 2)}
                            </pre>
                        </div>
                    </section>
                </div>
            </div>
        </div>
    );
};

export default CveDetail;
