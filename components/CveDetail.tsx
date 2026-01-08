import React, { useState, useEffect } from 'react';
import { ArrowLeft, ExternalLink, Shield, Calendar, Clock, Database, Copy, Check, ChevronDown, ChevronUp, Building2, Package, AlertTriangle, Target, History } from 'lucide-react';
import CvssVersionTabs from './CvssVersionTabs';

interface CveDetailProps {
    id: string;
    onBack: () => void;
    onApplyFilter?: (filter: { vendors?: string[]; products?: string[] }) => void;
}

const CveDetail: React.FC<CveDetailProps> = ({ id, onBack, onApplyFilter }) => {
    const [data, setData] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [copiedJson, setCopiedJson] = useState(false);
    const [showJson, setShowJson] = useState(false);
    const [showHistory, setShowHistory] = useState(false);

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

    // Reference tag colors
    const getTagColor = (tag: string) => {
        const t = tag.toLowerCase();
        if (t.includes('patch') || t.includes('fix')) return { bg: '#10b98120', border: '#10b98140', text: '#10b981' };
        if (t.includes('exploit') || t.includes('poc')) return { bg: '#ef444420', border: '#ef444440', text: '#ef4444' };
        if (t.includes('vendor')) return { bg: '#06b6d420', border: '#06b6d440', text: '#06b6d4' };
        if (t.includes('advisory')) return { bg: '#8b5cf620', border: '#8b5cf640', text: '#8b5cf6' };
        return { bg: '#6b728020', border: '#6b728040', text: '#9ca3af' };
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
                            <h1 className="text-4xl font-bold text-gray-100 mono tracking-tight mb-2">{id}</h1>
                            {data.title && (
                                <p className="text-gray-400 text-lg mb-4 leading-relaxed">{data.title}</p>
                            )}
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
                                {data.kev && (
                                    <span className="inline-flex items-center px-3 py-1.5 rounded-lg border text-sm mono font-medium"
                                        style={{
                                            background: 'rgba(239, 68, 68, 0.1)',
                                            borderColor: 'rgba(239, 68, 68, 0.4)',
                                            color: '#ef4444'
                                        }}
                                    >
                                        <Shield className="h-3.5 w-3.5 mr-2" strokeWidth={1.5} />
                                        KEV
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
                    {/* Description - Front and center */}
                    <section>
                        <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                            <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                            DESCRIPTION
                        </h2>
                        <p className="text-gray-300 leading-relaxed text-base pl-4">
                            {data.description}
                        </p>
                    </section>

                    {/* Vulnerability Details - CVSS + KEV + SSVC */}
                    <section>
                        <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                            <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                            Vulnerability details
                        </h2>

                        <CvssVersionTabs metrics={data.metrics || []} kev={data.kev} ssvc={data.ssvc} />
                    </section>

                    {/* CWE Classifications */}
                    {data.cwes && data.cwes.length > 0 && (
                        <section>
                            <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                PROBLEM TYPES ({data.cwes.length})
                            </h2>
                            <div className="space-y-2 pl-4">
                                {data.cwes.map((cwe: { cwe_id: string; description: string }, i: number) => (
                                    <div
                                        key={`${cwe.cwe_id}-${i}`}
                                        className="flex items-start gap-3 p-3 rounded-lg border"
                                        style={{
                                            background: 'rgba(239, 68, 68, 0.05)',
                                            borderColor: 'var(--cyber-border)'
                                        }}
                                    >
                                        <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5 flex-shrink-0" strokeWidth={1.5} />
                                        <div>
                                            <a
                                                href={`https://cwe.mitre.org/data/definitions/${cwe.cwe_id.replace('CWE-', '')}.html`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="text-red-400 mono text-sm font-medium hover:text-red-300 transition-colors"
                                            >
                                                {cwe.cwe_id}
                                            </a>
                                            {cwe.description && (
                                                <p className="text-gray-400 text-sm mt-1">{cwe.description}</p>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </section>
                    )}

                    {/* CAPEC Attack Patterns */}
                    {data.capecs && data.capecs.length > 0 && (
                        <section>
                            <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                ATTACK PATTERNS ({data.capecs.length})
                            </h2>
                            <div className="space-y-2 pl-4">
                                {data.capecs.map((capec: { capec_id: string; description: string }, i: number) => (
                                    <div
                                        key={`${capec.capec_id}-${i}`}
                                        className="flex items-start gap-3 p-3 rounded-lg border"
                                        style={{
                                            background: 'rgba(245, 158, 11, 0.05)',
                                            borderColor: 'var(--cyber-border)'
                                        }}
                                    >
                                        <Target className="h-4 w-4 text-amber-400 mt-0.5 flex-shrink-0" strokeWidth={1.5} />
                                        <div>
                                            <a
                                                href={`https://capec.mitre.org/data/definitions/${capec.capec_id.replace('CAPEC-', '')}.html`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="text-amber-400 mono text-sm font-medium hover:text-amber-300 transition-colors"
                                            >
                                                {capec.capec_id}
                                            </a>
                                            {capec.description && (
                                                <p className="text-gray-400 text-sm mt-1">{capec.description}</p>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </section>
                    )}

                    {/* Affected Products */}
                    {data.affectedProducts && data.affectedProducts.length > 0 && (
                        <section>
                            <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                AFFECTED PRODUCTS ({data.affectedProducts.length})
                            </h2>
                            <div className="space-y-3 pl-4">
                                {data.affectedProducts.map((item: {
                                    vendor: string;
                                    product: string;
                                    defaultStatus?: string;
                                    modules?: string[];
                                    versions?: Array<{
                                        version: string;
                                        status: string;
                                        lessThan?: string;
                                        lessThanOrEqual?: string;
                                        versionType?: string;
                                    }>;
                                }, i: number) => (
                                    <div
                                        key={`${item.vendor}-${item.product}-${i}`}
                                        className="p-3 rounded-lg border"
                                        style={{
                                            background: 'rgba(6, 182, 212, 0.05)',
                                            borderColor: 'var(--cyber-border)'
                                        }}
                                    >
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <button
                                                onClick={() => onApplyFilter?.({ vendors: [item.vendor] })}
                                                className="flex items-center gap-1.5 hover:opacity-80 transition-opacity cursor-pointer"
                                                title={`Filter by vendor: ${item.vendor}`}
                                            >
                                                <Building2 className="h-3.5 w-3.5 text-cyan-500" strokeWidth={1.5} />
                                                <span className="text-sm text-cyan-400 mono hover:text-cyan-300">{item.vendor}</span>
                                            </button>
                                            <span className="text-gray-600">/</span>
                                            <button
                                                onClick={() => onApplyFilter?.({ products: [item.product] })}
                                                className="flex items-center gap-1.5 hover:opacity-80 transition-opacity cursor-pointer"
                                                title={`Filter by product: ${item.product}`}
                                            >
                                                <Package className="h-3.5 w-3.5 text-purple-500" strokeWidth={1.5} />
                                                <span className="text-sm text-purple-400 mono hover:text-purple-300">{item.product}</span>
                                            </button>
                                            {item.defaultStatus && (
                                                <span className="text-xs px-2 py-0.5 rounded bg-gray-700/50 text-gray-400 mono">
                                                    {item.defaultStatus}
                                                </span>
                                            )}
                                        </div>
                                        {item.versions && item.versions.length > 0 && (
                                            <div className="mt-2 pl-5 space-y-1">
                                                {item.versions.map((v, vi) => (
                                                    <div key={vi} className="text-xs mono text-gray-400 flex items-center gap-2">
                                                        <span className={v.status === 'affected' ? 'text-red-400' : 'text-green-400'}>
                                                            {v.status === 'affected' ? 'affected' : 'fixed'}
                                                        </span>
                                                        <span className="text-gray-300">
                                                            {v.version}
                                                            {v.lessThan && ` - < ${v.lessThan}`}
                                                            {v.lessThanOrEqual && ` - <= ${v.lessThanOrEqual}`}
                                                        </span>
                                                        {v.versionType && (
                                                            <span className="text-gray-500">({v.versionType})</span>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                        {item.modules && item.modules.length > 0 && (
                                            <div className="mt-2 pl-5 flex flex-wrap gap-1">
                                                {item.modules.map((mod, mi) => (
                                                    <span key={mi} className="text-xs px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 mono border border-amber-500/20">
                                                        {mod}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </section>
                    )}

                    {/* Workarounds */}
                    {data.workarounds && data.workarounds.length > 0 && (
                        <section>
                            <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                                <div className="w-1 h-5 bg-amber-400 mr-3 rounded-full" />
                                WORKAROUNDS ({data.workarounds.length})
                            </h2>
                            <div className="space-y-3 pl-4">
                                {data.workarounds.map((w: { workaround_text: string; language?: string }, i: number) => (
                                    <div
                                        key={i}
                                        className="p-4 rounded-lg border"
                                        style={{
                                            background: 'rgba(245, 158, 11, 0.05)',
                                            borderColor: 'var(--cyber-border)'
                                        }}
                                    >
                                        <p className="text-gray-300 text-sm whitespace-pre-wrap">{w.workaround_text}</p>
                                    </div>
                                ))}
                            </div>
                        </section>
                    )}

                    {/* Solutions */}
                    {data.solutions && data.solutions.length > 0 && (
                        <section>
                            <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                                <div className="w-1 h-5 bg-green-400 mr-3 rounded-full" />
                                SOLUTIONS ({data.solutions.length})
                            </h2>
                            <div className="space-y-3 pl-4">
                                {data.solutions.map((s: { solution_text: string; language?: string }, i: number) => (
                                    <div
                                        key={i}
                                        className="p-4 rounded-lg border"
                                        style={{
                                            background: 'rgba(16, 185, 129, 0.05)',
                                            borderColor: 'var(--cyber-border)'
                                        }}
                                    >
                                        <p className="text-gray-300 text-sm whitespace-pre-wrap">{s.solution_text}</p>
                                    </div>
                                ))}
                            </div>
                        </section>
                    )}

                    {/* References */}
                    {data.references && data.references.length > 0 && (
                        <section>
                            <h2 className="text-lg font-semibold text-gray-100 mono mb-4 flex items-center">
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                REFERENCES ({data.references.length})
                            </h2>
                            <div className="space-y-2 pl-4">
                                {data.references.map((ref: { url: string; tags: string[] } | string, i: number) => {
                                    // Handle both old format (string) and new format ({url, tags})
                                    const url = typeof ref === 'string' ? ref : ref.url;
                                    const tags = typeof ref === 'string' ? [] : (ref.tags || []);

                                    return (
                                        <div
                                            key={i}
                                            className="group flex flex-col sm:flex-row sm:items-center gap-2 p-3 border rounded-lg transition-all hover:border-cyan-500/50"
                                            style={{
                                                background: 'rgba(6, 182, 212, 0.03)',
                                                borderColor: 'var(--cyber-border)'
                                            }}
                                        >
                                            <a
                                                href={url}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="flex items-center gap-2 flex-1 min-w-0"
                                            >
                                                <ExternalLink className="h-4 w-4 flex-shrink-0 text-gray-500 group-hover:text-cyan-400 transition-colors" strokeWidth={1.5} />
                                                <span className="text-sm text-cyan-400 truncate group-hover:text-cyan-300 transition-colors">
                                                    {url.replace(/^https?:\/\//, '')}
                                                </span>
                                            </a>
                                            {tags.length > 0 && (
                                                <div className="flex flex-wrap gap-1 flex-shrink-0">
                                                    {tags.map((tag: string, j: number) => {
                                                        const colors = getTagColor(tag);
                                                        return (
                                                            <span
                                                                key={j}
                                                                className="px-2 py-0.5 rounded text-xs mono border"
                                                                style={{
                                                                    backgroundColor: colors.bg,
                                                                    borderColor: colors.border,
                                                                    color: colors.text
                                                                }}
                                                            >
                                                                {tag}
                                                            </span>
                                                        );
                                                    })}
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </section>
                    )}

                    {/* Change History - Collapsible */}
                    {data.changeHistory && data.changeHistory.length > 0 && (
                        <section>
                            <button
                                onClick={() => setShowHistory(!showHistory)}
                                className="flex items-center text-lg font-semibold text-gray-100 mono hover:text-cyan-400 transition-colors mb-4"
                            >
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                CHANGE HISTORY ({data.changeHistory.length})
                                {showHistory ? (
                                    <ChevronUp className="h-5 w-5 ml-2 text-gray-500" strokeWidth={1.5} />
                                ) : (
                                    <ChevronDown className="h-5 w-5 ml-2 text-gray-500" strokeWidth={1.5} />
                                )}
                            </button>
                            {showHistory && (
                                <div className="space-y-3 pl-4">
                                    {data.changeHistory.map((change: { date: string; changes: Record<string, { from: any; to: any }> }, i: number) => (
                                        <div
                                            key={i}
                                            className="p-4 rounded-lg border"
                                            style={{
                                                background: 'rgba(6, 182, 212, 0.03)',
                                                borderColor: 'var(--cyber-border)'
                                            }}
                                        >
                                            <div className="flex items-center gap-2 mb-3">
                                                <History className="h-4 w-4 text-cyan-500" strokeWidth={1.5} />
                                                <span className="text-sm text-cyan-400 mono">
                                                    {new Date(change.date).toLocaleString()}
                                                </span>
                                            </div>
                                            <div className="space-y-2">
                                                {Object.entries(change.changes).map(([field, diff]) => (
                                                    <div key={field} className="text-sm">
                                                        <span className="text-gray-500 mono">{field}:</span>
                                                        <div className="ml-4 mt-1 text-xs">
                                                            <div className="text-red-400/70 line-through truncate">
                                                                {typeof diff.from === 'object' ? JSON.stringify(diff.from) : String(diff.from)}
                                                            </div>
                                                            <div className="text-green-400 truncate">
                                                                {typeof diff.to === 'object' ? JSON.stringify(diff.to) : String(diff.to)}
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </section>
                    )}

                    {/* Raw JSON - Collapsible */}
                    <section>
                        <div className="flex items-center justify-between">
                            <button
                                onClick={() => setShowJson(!showJson)}
                                className="flex items-center text-lg font-semibold text-gray-100 mono hover:text-cyan-400 transition-colors"
                            >
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                RAW DATA
                                {showJson ? (
                                    <ChevronUp className="h-5 w-5 ml-2 text-gray-500" strokeWidth={1.5} />
                                ) : (
                                    <ChevronDown className="h-5 w-5 ml-2 text-gray-500" strokeWidth={1.5} />
                                )}
                            </button>
                            {showJson && (
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
                            )}
                        </div>
                        {showJson && (
                            <div className="rounded-lg border p-6 overflow-auto max-h-96 mt-4" style={{
                                background: '#000000',
                                borderColor: 'var(--cyber-border)'
                            }}>
                                <pre className="text-green-400 text-xs leading-relaxed mono">
                                    {JSON.stringify(data, null, 2)}
                                </pre>
                            </div>
                        )}
                    </section>
                </div>
            </div>
        </div>
    );
};

export default CveDetail;
