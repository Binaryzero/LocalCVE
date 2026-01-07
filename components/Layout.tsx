import React from 'react';
import { ShieldAlert, Bell, Activity, Database, Menu, X, Terminal } from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
  activePage: string;
  onNavigate: (page: string) => void;
}

const Layout: React.FC<LayoutProps> = ({ children, activePage, onNavigate }) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);

  const NavItem = ({ id, label, icon: Icon }: { id: string; label: string; icon: any }) => (
    <button
      onClick={() => {
        onNavigate(id);
        setIsMobileMenuOpen(false);
      }}
      className={`group w-full flex items-center px-4 py-3 text-sm font-medium transition-all duration-200 relative overflow-hidden ${
        activePage === id
          ? 'text-cyan-400'
          : 'text-gray-400 hover:text-cyan-300'
      }`}
    >
      {/* Active indicator */}
      <div className={`absolute left-0 top-0 h-full w-1 bg-gradient-to-b from-cyan-400 to-cyan-600 transition-all duration-300 ${
        activePage === id ? 'opacity-100' : 'opacity-0'
      }`} />

      {/* Hover background */}
      <div className={`absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-200 ${
        activePage === id ? 'opacity-100' : ''
      }`} />

      <Icon className={`relative z-10 mr-3 h-5 w-5 transition-transform duration-200 group-hover:scale-110 ${
        activePage === id ? 'text-cyan-400' : 'text-gray-500 group-hover:text-cyan-400'
      }`} />
      <span className="relative z-10 mono tracking-wide">{label}</span>

      {/* Glitch effect on active */}
      {activePage === id && (
        <div className="absolute right-4 w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
      )}
    </button>
  );

  return (
    <div className="min-h-screen flex" style={{ background: 'var(--cyber-bg)' }}>
      {/* Sidebar for Desktop */}
      <div className="hidden md:flex flex-col w-72 border-r fixed h-full z-10" style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        {/* Header */}
        <div className="flex items-center h-20 px-6 border-b relative" style={{ borderColor: 'var(--cyber-border)' }}>
          <div className="flex items-center space-x-3">
            <div className="relative">
              <ShieldAlert className="h-9 w-9 text-cyan-400" strokeWidth={1.5} />
              <div className="absolute inset-0 bg-cyan-400/20 blur-xl rounded-full" />
            </div>
            <div>
              <span className="mono text-xl font-bold text-gray-100 tracking-tight">CVE <span className="text-cyan-400">Tracker</span></span>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-6 space-y-1 overflow-y-auto">
          <div className="mb-4">
            <div className="px-4 mb-2 text-xs font-semibold text-gray-600 uppercase tracking-wider mono">
              Search
            </div>
            <NavItem id="cves" label="CVEs" icon={Database} />
            <NavItem id="alerts" label="Alerts" icon={Bell} />
          </div>

          <div className="mb-4">
            <div className="px-4 mb-2 text-xs font-semibold text-gray-600 uppercase tracking-wider mono">
              Manage
            </div>
            <NavItem id="watchlists" label="Watchlists" icon={Activity} />
            <NavItem id="jobs" label="Ingestion" icon={Terminal} />
          </div>
        </nav>

      </div>

      {/* Mobile Header */}
      <div className="md:hidden fixed w-full border-b z-20" style={{
        background: 'var(--cyber-surface)',
        borderColor: 'var(--cyber-border)'
      }}>
        <div className="flex items-center justify-between h-16 px-4">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="h-7 w-7 text-cyan-400" strokeWidth={1.5} />
            <span className="mono text-lg font-bold text-gray-100">CVE <span className="text-cyan-400">Tracker</span></span>
          </div>
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="p-2 rounded-md text-gray-400 hover:text-cyan-400 hover:bg-gray-800/50 transition-all"
          >
            {isMobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      {isMobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-30 pt-16" style={{ background: 'var(--cyber-surface)' }}>
          <nav className="px-4 py-6 space-y-1">
            <NavItem id="cves" label="CVEs" icon={Database} />
            <NavItem id="alerts" label="Alerts" icon={Bell} />
            <NavItem id="watchlists" label="Watchlists" icon={Activity} />
            <NavItem id="jobs" label="Ingestion" icon={Terminal} />
          </nav>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 md:ml-72 p-4 md:p-8 pt-20 md:pt-8 overflow-y-auto">
        <div className="max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;
