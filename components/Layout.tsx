import React from 'react';
import { LayoutDashboard, ShieldAlert, Bell, Activity, Database, Menu, X } from 'lucide-react';

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
      className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors duration-150 ${
        activePage === id
          ? 'bg-blue-50 text-blue-700'
          : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
      }`}
    >
      <Icon className={`mr-3 h-5 w-5 ${activePage === id ? 'text-blue-700' : 'text-gray-400'}`} />
      {label}
    </button>
  );

  return (
    <div className="min-h-screen flex bg-gray-50">
      {/* Sidebar for Desktop */}
      <div className="hidden md:flex flex-col w-64 bg-white border-r border-gray-200 fixed h-full z-10">
        <div className="flex items-center h-16 px-6 border-b border-gray-200">
          <ShieldAlert className="h-8 w-8 text-blue-600 mr-2" />
          <span className="text-xl font-bold text-gray-800">CVE Tracker</span>
        </div>
        <nav className="flex-1 px-4 py-6 space-y-1">
          <NavItem id="dashboard" label="Dashboard" icon={LayoutDashboard} />
          <NavItem id="cves" label="CVEs" icon={Database} />
          <NavItem id="watchlists" label="Watchlists" icon={Activity} />
          <NavItem id="alerts" label="Alerts" icon={Bell} />
          <NavItem id="jobs" label="Jobs" icon={Activity} />
        </nav>
        <div className="p-4 border-t border-gray-200">
          <p className="text-xs text-gray-500">Local Single-User Mode</p>
          <p className="text-xs text-gray-400 mt-1">v1.0.0</p>
        </div>
      </div>

      {/* Mobile Header */}
      <div className="md:hidden fixed w-full bg-white border-b border-gray-200 z-20">
        <div className="flex items-center justify-between h-16 px-4">
          <div className="flex items-center">
            <ShieldAlert className="h-8 w-8 text-blue-600 mr-2" />
            <span className="text-xl font-bold text-gray-800">CVE Tracker</span>
          </div>
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100"
          >
            {isMobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      {isMobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-30 bg-white pt-16">
           <nav className="px-4 py-6 space-y-1">
            <NavItem id="dashboard" label="Dashboard" icon={LayoutDashboard} />
            <NavItem id="cves" label="CVEs" icon={Database} />
            <NavItem id="watchlists" label="Watchlists" icon={Activity} />
            <NavItem id="alerts" label="Alerts" icon={Bell} />
            <NavItem id="jobs" label="Jobs" icon={Activity} />
          </nav>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 md:ml-64 p-4 md:p-8 pt-20 md:pt-8 overflow-y-auto">
        <div className="max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;
