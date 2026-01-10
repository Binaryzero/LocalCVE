import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ArrowLeft, ExternalLink, Shield, Calendar, Clock, Database, Copy, Check, ChevronDown, ChevronUp, ChevronLeft, ChevronRight, Building2, Package, AlertTriangle, Target, History, ChevronsDown } from 'lucide-react';
import CvssVersionTabs from './CvssVersionTabs';

// Scrollable container with visual scroll indicators
const ScrollableList: React.FC<{
    children: React.ReactNode;
    maxHeight?: string;
    className?: string;
    threshold?: number; // Number of items before showing scroll container
    itemCount: number;
}> = ({ children, maxHeight = '15rem', className = '', threshold = 5, itemCount }) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const [showTopFade, setShowTopFade] = useState(false);
    const [showBottomFade, setShowBottomFade] = useState(false);

    const checkScroll = useCallback(() => {
        const el = containerRef.current;
        if (!el) return;

        const { scrollTop, scrollHeight, clientHeight } = el;
        const isScrollable = scrollHeight > clientHeight;

        setShowTopFade(isScrollable && scrollTop > 10);
        setShowBottomFade(isScrollable && scrollTop < scrollHeight - clientHeight - 10);
    }, []);

    useEffect(() => {
        checkScroll();
        const el = containerRef.current;
        if (el) {
            el.addEventListener('scroll', checkScroll);
            // Check on resize too
            const resizeObserver = new ResizeObserver(checkScroll);
            resizeObserver.observe(el);
            return () => {
                el.removeEventListener('scroll', checkScroll);
                resizeObserver.disconnect();
            };
        }
    }, [checkScroll, itemCount]);

    // Don't apply scrolling if under threshold
    if (itemCount <= threshold) {
        return <div className={className}>{children}</div>;
    }

    return (
        <div className="relative">
            {/* Top fade indicator */}
            {showTopFade && (
                <div
                    className="absolute top-0 left-0 right-0 h-6 pointer-events-none z-10"
                    style={{
                        background: 'linear-gradient(to bottom, rgba(10, 10, 10, 0.95), transparent)'
                    }}
                />
            )}

            {/* Scrollable content */}
            <div
                ref={containerRef}
                className={`overflow-y-auto ${className}`}
                style={{ maxHeight }}
            >
                {children}
            </div>

            {/* Bottom fade indicator with scroll hint */}
            {showBottomFade && (
                <div
                    className="absolute bottom-0 left-0 right-0 h-8 pointer-events-none z-10 flex items-end justify-center"
                    style={{
                        background: 'linear-gradient(to top, rgba(10, 10, 10, 0.95), transparent)'
                    }}
                >
                    <ChevronsDown className="h-4 w-4 text-gray-500 mb-1 animate-bounce" style={{ animationDuration: '2s' }} />
                </div>
            )}
        </div>
    );
};

interface CveDetailProps {
    id: string;
    onBack: () => void;
    onApplyFilter?: (filter: { vendors?: string[]; products?: string[] }) => void;
    onNavigatePrev?: () => void;
    onNavigateNext?: () => void;
    currentIndex?: number;
    totalCount?: number;
    showBackButton?: boolean;
}

const CveDetail: React.FC<CveDetailProps> = ({ id, onBack, onApplyFilter, onNavigatePrev, onNavigateNext, currentIndex, totalCount, showBackButton = true }) => {
    const [data, setData] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [copiedJson, setCopiedJson] = useState(false);
    const [showJson, setShowJson] = useState(false);
    const [showHistory, setShowHistory] = useState(false);
    const [showExploits, setShowExploits] = useState(false);
    const [showReferences, setShowReferences] = useState(false);

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

    // Keyboard navigation: left/right arrows or j/k for prev/next
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            // Don't trigger if user is typing in an input
            if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

            if ((e.key === 'ArrowLeft' || e.key === 'k') && onNavigatePrev) {
                e.preventDefault();
                onNavigatePrev();
            } else if ((e.key === 'ArrowRight' || e.key === 'j') && onNavigateNext) {
                e.preventDefault();
                onNavigateNext();
            } else if (e.key === 'Escape') {
                e.preventDefault();
                onBack();
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [onNavigatePrev, onNavigateNext, onBack]);

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
            {/* Navigation Bar */}
            <div className="flex items-center justify-between">
                {/* Back Button */}
                {showBackButton && (
                    <button
                        onClick={onBack}
                        className="inline-flex items-center text-cyan-400 hover:text-cyan-300 transition-colors mono text-sm font-medium"
                    >
                        <ArrowLeft className="h-4 w-4 mr-2" strokeWidth={1.5} />
                        BACK TO LIST
                    </button>
                )}

                {/* Prev/Next Navigation */}
                {totalCount !== undefined && totalCount > 0 && (
                    <div className="flex items-center gap-2">
                        <button
                            onClick={onNavigatePrev}
                            disabled={!onNavigatePrev}
                            className={`inline-flex items-center gap-1 px-3 py-1.5 rounded border transition-colors mono text-sm ${
                                onNavigatePrev
                                    ? 'text-gray-300 border-gray-700 hover:border-cyan-500 hover:text-cyan-400 hover:bg-cyan-500/10'
                                    : 'text-gray-600 border-gray-800 cursor-not-allowed'
                            }`}
                            title="Previous CVE"
                        >
                            <ChevronLeft className="h-4 w-4" strokeWidth={1.5} />
                            PREV
                        </button>

                        <span className="text-gray-500 mono text-sm px-2">
                            {currentIndex !== undefined ? currentIndex + 1 : '?'} / {totalCount}
                        </span>

                        <button
                            onClick={onNavigateNext}
                            disabled={!onNavigateNext}
                            className={`inline-flex items-center gap-1 px-3 py-1.5 rounded border transition-colors mono text-sm ${
                                onNavigateNext
                                    ? 'text-gray-300 border-gray-700 hover:border-cyan-500 hover:text-cyan-400 hover:bg-cyan-500/10'
                                    : 'text-gray-600 border-gray-800 cursor-not-allowed'
                            }`}
                            title="Next CVE"
                        >
                            NEXT
                            <ChevronRight className="h-4 w-4" strokeWidth={1.5} />
                        </button>
                    </div>
                )}
            </div>

            {/* Main Card */}
            <div className="rounded-lg border overflow-hidden" style={{
                background: 'var(--cyber-surface)',
                borderColor: 'var(--cyber-border)'
            }}>
                {/* Header */}
                <div className="px-8 py-6 border-b" style={{
                    borderColor: 'var(--cyber-border)',
                    background: 'rgba(6, 182, 212, 0.03)'
                }}>
                    <div className="flex justify-between items-start gap-6">
                        {/* Left side: ID, status, title */}
                        <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                                <h1 className="text-3xl font-bold text-gray-100 mono tracking-tight">{id}</h1>
                                <span className="inline-flex items-center px-2 py-0.5 rounded border text-xs mono font-medium"
                                    style={{
                                        background: 'rgba(6, 182, 212, 0.1)',
                                        borderColor: 'var(--cyber-accent)',
                                        color: 'var(--cyber-accent)'
                                    }}
                                >
                                    {data.vulnStatus || 'PUBLISHED'}
                                </span>
                            </div>
                            {data.title && (
                                <p className="text-gray-400 text-base leading-relaxed">{data.title}</p>
                            )}
                        </div>
                        {/* Right side: Dates */}
                        <div className="flex flex-col gap-2 text-sm text-gray-500 mono text-right">
                            <span className="flex items-center justify-end">
                                <Calendar className="h-4 w-4 mr-2" strokeWidth={1.5} />
                                {new Date(data.published).toLocaleDateString()}
                            </span>
                            <span className="flex items-center justify-end">
                                <Clock className="h-4 w-4 mr-2" strokeWidth={1.5} />
                                {new Date(data.lastModified).toLocaleDateString()}
                            </span>
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

                        {/* Temporal Enrichment - EPSS, Exploit Maturity & Sources */}
                        {data.temporal && (
                            <div className="mt-6 p-3 rounded-lg border flex flex-wrap items-center gap-3" style={{
                                background: 'var(--cyber-surface)',
                                borderColor: 'var(--cyber-border)'
                            }}>
                                {/* EPSS Score */}
                                <div className="flex items-center gap-2">
                                    <span className="text-xs text-gray-500 mono">EPSS</span>
                                    <span className={`px-2 py-0.5 rounded text-xs font-bold mono ${
                                        data.temporal.epss >= 0.5 ? 'bg-red-500/20 text-red-400' :
                                        data.temporal.epss >= 0.2 ? 'bg-orange-500/20 text-orange-400' :
                                        data.temporal.epss >= 0.05 ? 'bg-amber-500/20 text-amber-400' :
                                        'bg-gray-500/20 text-gray-400'
                                    }`}>
                                        {(data.temporal.epss * 100).toFixed(1)}%
                                    </span>
                                </div>

                                <span className="text-gray-700">|</span>

                                {/* Exploit Maturity */}
                                <div className="flex items-center gap-2">
                                    <span className="text-xs text-gray-500 mono">MATURITY</span>
                                    <span className={`px-2 py-0.5 rounded text-xs font-bold mono ${
                                        data.temporal.exploitMaturity === 'A' ? 'bg-red-500/20 text-red-400' :
                                        data.temporal.exploitMaturity === 'H' ? 'bg-orange-500/20 text-orange-400' :
                                        data.temporal.exploitMaturity === 'F' ? 'bg-amber-500/20 text-amber-400' :
                                        data.temporal.exploitMaturity === 'POC' ? 'bg-yellow-500/20 text-yellow-400' :
                                        'bg-gray-500/20 text-gray-400'
                                    }`}>
                                        {data.temporal.exploitMaturity === 'A' ? 'ATTACKED' :
                                         data.temporal.exploitMaturity === 'H' ? 'HIGH' :
                                         data.temporal.exploitMaturity === 'F' ? 'FUNCTIONAL' :
                                         data.temporal.exploitMaturity === 'POC' ? 'POC' :
                                         'UNPROVEN'}
                                    </span>
                                </div>

                                {/* Exploit Sources - Based on actual exploit links, not CVSS-BT flags */}
                                {data.exploits && Object.keys(data.exploits).length > 0 && (
                                    <>
                                        <span className="text-gray-700">|</span>
                                        <div className="flex items-center gap-2">
                                            <span className="text-xs text-gray-500 mono">EXPLOITS</span>
                                            <div className="flex flex-wrap gap-1">
                                                {data.exploits.github?.length > 0 && (
                                                    <button
                                                       onClick={() => { setShowExploits(true); setTimeout(() => document.getElementById('exploits-github')?.scrollIntoView({ behavior: 'smooth' }), 100); }}
                                                       className="px-1.5 py-0.5 rounded text-xs mono bg-gray-500/20 text-gray-400 hover:bg-gray-500/30 transition-colors cursor-pointer">
                                                        GitHub ({data.exploits.github.length})
                                                    </button>
                                                )}
                                                {data.exploits.metasploit?.length > 0 && (
                                                    <button
                                                       onClick={() => { setShowExploits(true); setTimeout(() => document.getElementById('exploits-metasploit')?.scrollIntoView({ behavior: 'smooth' }), 100); }}
                                                       className="px-1.5 py-0.5 rounded text-xs mono bg-orange-500/20 text-orange-400 hover:bg-orange-500/30 transition-colors cursor-pointer">
                                                        MSF ({data.exploits.metasploit.length})
                                                    </button>
                                                )}
                                                {data.exploits.exploitdb?.length > 0 && (
                                                    <button
                                                       onClick={() => { setShowExploits(true); setTimeout(() => document.getElementById('exploits-exploitdb')?.scrollIntoView({ behavior: 'smooth' }), 100); }}
                                                       className="px-1.5 py-0.5 rounded text-xs mono bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 transition-colors cursor-pointer">
                                                        EDB ({data.exploits.exploitdb.length})
                                                    </button>
                                                )}
                                                {data.exploits.nuclei?.length > 0 && (
                                                    <button
                                                       onClick={() => { setShowExploits(true); setTimeout(() => document.getElementById('exploits-nuclei')?.scrollIntoView({ behavior: 'smooth' }), 100); }}
                                                       className="px-1.5 py-0.5 rounded text-xs mono bg-amber-500/20 text-amber-400 hover:bg-amber-500/30 transition-colors cursor-pointer">
                                                        Nuclei ({data.exploits.nuclei.length})
                                                    </button>
                                                )}
                                                {data.exploits.packetstorm?.length > 0 && (
                                                    <button
                                                       onClick={() => { setShowExploits(true); setTimeout(() => document.getElementById('exploits-packetstorm')?.scrollIntoView({ behavior: 'smooth' }), 100); }}
                                                       className="px-1.5 py-0.5 rounded text-xs mono bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 transition-colors cursor-pointer">
                                                        PS ({data.exploits.packetstorm.length})
                                                    </button>
                                                )}
                                                {data.exploits.cisa?.length > 0 && (
                                                    <button
                                                       onClick={() => { setShowExploits(true); setTimeout(() => document.getElementById('exploits-cisa')?.scrollIntoView({ behavior: 'smooth' }), 100); }}
                                                       className="px-1.5 py-0.5 rounded text-xs mono bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors cursor-pointer">
                                                        CISA ({data.exploits.cisa.length})
                                                    </button>
                                                )}
                                                {data.exploits.hackerone?.length > 0 && (
                                                    <button
                                                       onClick={() => { setShowExploits(true); setTimeout(() => document.getElementById('exploits-hackerone')?.scrollIntoView({ behavior: 'smooth' }), 100); }}
                                                       className="px-1.5 py-0.5 rounded text-xs mono bg-pink-500/20 text-pink-400 hover:bg-pink-500/30 transition-colors cursor-pointer">
                                                        H1 ({data.exploits.hackerone.length})
                                                    </button>
                                                )}
                                                {data.exploits.reference?.length > 0 && (
                                                    <button
                                                       onClick={() => { setShowExploits(true); setTimeout(() => document.getElementById('exploits-reference')?.scrollIntoView({ behavior: 'smooth' }), 100); }}
                                                       className="px-1.5 py-0.5 rounded text-xs mono bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors cursor-pointer">
                                                        Other ({data.exploits.reference.length})
                                                    </button>
                                                )}
                                            </div>
                                        </div>
                                    </>
                                )}
                            </div>
                        )}
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

                    {/* References - Collapsible */}
                    {data.references && data.references.length > 0 && (
                        <section>
                            <button
                                onClick={() => setShowReferences(!showReferences)}
                                className="flex items-center text-lg font-semibold text-gray-100 mono hover:text-cyan-400 transition-colors mb-4"
                            >
                                <div className="w-1 h-5 bg-cyan-400 mr-3 rounded-full" />
                                REFERENCES ({data.references.length})
                                {showReferences ? (
                                    <ChevronUp className="h-5 w-5 ml-2 text-gray-500" strokeWidth={1.5} />
                                ) : (
                                    <ChevronDown className="h-5 w-5 ml-2 text-gray-500" strokeWidth={1.5} />
                                )}
                            </button>
                            {showReferences && (
                                <ScrollableList itemCount={data.references.length} className="space-y-2 pl-4">
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
                                </ScrollableList>
                            )}
                        </section>
                    )}

                    {/* Exploit References - Collapsible (from Trickest) */}
                    {data.exploits && Object.keys(data.exploits).length > 0 && (
                        <section id="exploits-section">
                            <button
                                onClick={() => setShowExploits(!showExploits)}
                                className="flex items-center text-lg font-semibold text-gray-100 mono hover:text-cyan-400 transition-colors mb-4"
                            >
                                <div className="w-1 h-5 bg-red-500 mr-3 rounded-full" />
                                EXPLOIT REFERENCES ({Object.values(data.exploits).flat().length})
                                {showExploits ? (
                                    <ChevronUp className="h-5 w-5 ml-2 text-gray-500" strokeWidth={1.5} />
                                ) : (
                                    <ChevronDown className="h-5 w-5 ml-2 text-gray-500" strokeWidth={1.5} />
                                )}
                            </button>
                            {showExploits && (
                                <div className="space-y-4 pl-4">
                                    {/* GitHub PoCs */}
                                    {data.exploits.github && data.exploits.github.length > 0 && (
                                        <div id="exploits-github">
                                            <h3 className="text-sm font-semibold text-gray-400 mono mb-2 flex items-center gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-xs bg-gray-500/20 text-gray-400">GitHub</span>
                                                <span className="text-gray-600">({data.exploits.github.length})</span>
                                            </h3>
                                            <ScrollableList itemCount={data.exploits.github.length} className="space-y-1">
                                                {data.exploits.github.map((exploit: { url: string }, i: number) => (
                                                    <a
                                                        key={i}
                                                        href={exploit.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="flex items-center gap-2 p-2 rounded border border-transparent hover:border-gray-700 hover:bg-gray-900/50 transition-all group"
                                                    >
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0 text-gray-600 group-hover:text-gray-400" strokeWidth={1.5} />
                                                        <span className="text-xs text-gray-500 group-hover:text-gray-300 truncate mono">
                                                            {exploit.url.replace('https://github.com/', '')}
                                                        </span>
                                                    </a>
                                                ))}
                                            </ScrollableList>
                                        </div>
                                    )}

                                    {/* Metasploit */}
                                    {data.exploits.metasploit && data.exploits.metasploit.length > 0 && (
                                        <div id="exploits-metasploit">
                                            <h3 className="text-sm font-semibold text-gray-400 mono mb-2 flex items-center gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-xs bg-orange-500/20 text-orange-400">Metasploit</span>
                                                <span className="text-gray-600">({data.exploits.metasploit.length})</span>
                                            </h3>
                                            <ScrollableList itemCount={data.exploits.metasploit.length} className="space-y-1">
                                                {data.exploits.metasploit.map((exploit: { url: string }, i: number) => (
                                                    <a
                                                        key={i}
                                                        href={exploit.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="flex items-center gap-2 p-2 rounded border border-transparent hover:border-orange-700/50 hover:bg-orange-900/10 transition-all group"
                                                    >
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0 text-orange-600 group-hover:text-orange-400" strokeWidth={1.5} />
                                                        <span className="text-xs text-orange-500/70 group-hover:text-orange-300 truncate mono">
                                                            {exploit.url.replace(/^https?:\/\//, '')}
                                                        </span>
                                                    </a>
                                                ))}
                                            </ScrollableList>
                                        </div>
                                    )}

                                    {/* ExploitDB */}
                                    {data.exploits.exploitdb && data.exploits.exploitdb.length > 0 && (
                                        <div id="exploits-exploitdb">
                                            <h3 className="text-sm font-semibold text-gray-400 mono mb-2 flex items-center gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-xs bg-yellow-500/20 text-yellow-400">ExploitDB</span>
                                                <span className="text-gray-600">({data.exploits.exploitdb.length})</span>
                                            </h3>
                                            <ScrollableList itemCount={data.exploits.exploitdb.length} className="space-y-1">
                                                {data.exploits.exploitdb.map((exploit: { url: string }, i: number) => (
                                                    <a
                                                        key={i}
                                                        href={exploit.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="flex items-center gap-2 p-2 rounded border border-transparent hover:border-yellow-700/50 hover:bg-yellow-900/10 transition-all group"
                                                    >
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0 text-yellow-600 group-hover:text-yellow-400" strokeWidth={1.5} />
                                                        <span className="text-xs text-yellow-500/70 group-hover:text-yellow-300 truncate mono">
                                                            {exploit.url.replace(/^https?:\/\//, '')}
                                                        </span>
                                                    </a>
                                                ))}
                                            </ScrollableList>
                                        </div>
                                    )}

                                    {/* Nuclei */}
                                    {data.exploits.nuclei && data.exploits.nuclei.length > 0 && (
                                        <div id="exploits-nuclei">
                                            <h3 className="text-sm font-semibold text-gray-400 mono mb-2 flex items-center gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-xs bg-amber-500/20 text-amber-400">Nuclei</span>
                                                <span className="text-gray-600">({data.exploits.nuclei.length})</span>
                                            </h3>
                                            <ScrollableList itemCount={data.exploits.nuclei.length} className="space-y-1">
                                                {data.exploits.nuclei.map((exploit: { url: string }, i: number) => (
                                                    <a
                                                        key={i}
                                                        href={exploit.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="flex items-center gap-2 p-2 rounded border border-transparent hover:border-amber-700/50 hover:bg-amber-900/10 transition-all group"
                                                    >
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0 text-amber-600 group-hover:text-amber-400" strokeWidth={1.5} />
                                                        <span className="text-xs text-amber-500/70 group-hover:text-amber-300 truncate mono">
                                                            {exploit.url.replace('https://github.com/', '')}
                                                        </span>
                                                    </a>
                                                ))}
                                            </ScrollableList>
                                        </div>
                                    )}

                                    {/* PacketStorm */}
                                    {data.exploits.packetstorm && data.exploits.packetstorm.length > 0 && (
                                        <div id="exploits-packetstorm">
                                            <h3 className="text-sm font-semibold text-gray-400 mono mb-2 flex items-center gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-xs bg-purple-500/20 text-purple-400">PacketStorm</span>
                                                <span className="text-gray-600">({data.exploits.packetstorm.length})</span>
                                            </h3>
                                            <ScrollableList itemCount={data.exploits.packetstorm.length} className="space-y-1">
                                                {data.exploits.packetstorm.map((exploit: { url: string }, i: number) => (
                                                    <a
                                                        key={i}
                                                        href={exploit.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="flex items-center gap-2 p-2 rounded border border-transparent hover:border-purple-700/50 hover:bg-purple-900/10 transition-all group"
                                                    >
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0 text-purple-600 group-hover:text-purple-400" strokeWidth={1.5} />
                                                        <span className="text-xs text-purple-500/70 group-hover:text-purple-300 truncate mono">
                                                            {exploit.url.replace(/^https?:\/\//, '')}
                                                        </span>
                                                    </a>
                                                ))}
                                            </ScrollableList>
                                        </div>
                                    )}

                                    {/* CISA */}
                                    {data.exploits.cisa && data.exploits.cisa.length > 0 && (
                                        <div id="exploits-cisa">
                                            <h3 className="text-sm font-semibold text-gray-400 mono mb-2 flex items-center gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-xs bg-red-500/20 text-red-400">CISA</span>
                                                <span className="text-gray-600">({data.exploits.cisa.length})</span>
                                            </h3>
                                            <ScrollableList itemCount={data.exploits.cisa.length} className="space-y-1">
                                                {data.exploits.cisa.map((exploit: { url: string }, i: number) => (
                                                    <a
                                                        key={i}
                                                        href={exploit.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="flex items-center gap-2 p-2 rounded border border-transparent hover:border-red-700/50 hover:bg-red-900/10 transition-all group"
                                                    >
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0 text-red-600 group-hover:text-red-400" strokeWidth={1.5} />
                                                        <span className="text-xs text-red-500/70 group-hover:text-red-300 truncate mono">
                                                            {exploit.url.replace(/^https?:\/\//, '')}
                                                        </span>
                                                    </a>
                                                ))}
                                            </ScrollableList>
                                        </div>
                                    )}

                                    {/* HackerOne */}
                                    {data.exploits.hackerone && data.exploits.hackerone.length > 0 && (
                                        <div id="exploits-hackerone">
                                            <h3 className="text-sm font-semibold text-gray-400 mono mb-2 flex items-center gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-xs bg-pink-500/20 text-pink-400">HackerOne</span>
                                                <span className="text-gray-600">({data.exploits.hackerone.length})</span>
                                            </h3>
                                            <ScrollableList itemCount={data.exploits.hackerone.length} className="space-y-1">
                                                {data.exploits.hackerone.map((exploit: { url: string }, i: number) => (
                                                    <a
                                                        key={i}
                                                        href={exploit.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="flex items-center gap-2 p-2 rounded border border-transparent hover:border-pink-700/50 hover:bg-pink-900/10 transition-all group"
                                                    >
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0 text-pink-600 group-hover:text-pink-400" strokeWidth={1.5} />
                                                        <span className="text-xs text-pink-500/70 group-hover:text-pink-300 truncate mono">
                                                            {exploit.url.replace(/^https?:\/\//, '')}
                                                        </span>
                                                    </a>
                                                ))}
                                            </ScrollableList>
                                        </div>
                                    )}

                                    {/* Other References */}
                                    {data.exploits.reference && data.exploits.reference.length > 0 && (
                                        <div id="exploits-reference">
                                            <h3 className="text-sm font-semibold text-gray-400 mono mb-2 flex items-center gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-xs bg-cyan-500/20 text-cyan-400">Other</span>
                                                <span className="text-gray-600">({data.exploits.reference.length})</span>
                                            </h3>
                                            <ScrollableList itemCount={data.exploits.reference.length} className="space-y-1">
                                                {data.exploits.reference.map((exploit: { url: string }, i: number) => (
                                                    <a
                                                        key={i}
                                                        href={exploit.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="flex items-center gap-2 p-2 rounded border border-transparent hover:border-cyan-700/50 hover:bg-cyan-900/10 transition-all group"
                                                    >
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0 text-cyan-600 group-hover:text-cyan-400" strokeWidth={1.5} />
                                                        <span className="text-xs text-cyan-500/70 group-hover:text-cyan-300 truncate mono">
                                                            {exploit.url.replace(/^https?:\/\//, '')}
                                                        </span>
                                                    </a>
                                                ))}
                                            </ScrollableList>
                                        </div>
                                    )}
                                </div>
                            )}
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
