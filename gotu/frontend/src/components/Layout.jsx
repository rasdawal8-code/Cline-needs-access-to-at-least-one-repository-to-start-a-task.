import React from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/auth.js';
import { Shield, Search, LayoutDashboard, Database, Settings, LogOut, Radio } from 'lucide-react';

const NAV = [
  { to: '/dashboard',          icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/investigations/new', icon: Search,          label: 'New Investigation' },
  { to: '/sources',            icon: Database,        label: 'Sources' },
  { to: '/security',           icon: Settings,        label: 'Security' },
];

export default function Layout() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();
  const handleLogout = async () => { await logout(); navigate('/login'); };
  return (
    <div className="flex h-screen bg-gotu-bg overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 border-r border-gotu-border bg-gotu-surface flex flex-col">
        {/* Logo */}
        <div className="p-4 border-b border-gotu-border">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-gotu-accent flex items-center justify-center">
              <Shield size={16} className="text-gotu-bg" />
            </div>
            <div>
              <div className="text-sm font-bold text-gotu-accent tracking-widest">GOTU</div>
              <div className="text-xs text-gotu-muted">Intelligence</div>
            </div>
          </div>
        </div>
        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive ? 'bg-gotu-accent bg-opacity-10 text-gotu-accent border border-gotu-accent border-opacity-30'
                           : 'text-gotu-muted hover:text-gotu-text hover:bg-gotu-border'}`
              }>
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>
        {/* User info */}
        <div className="p-3 border-t border-gotu-border">
          <div className="flex items-center gap-2 px-3 py-2 rounded-md">
            <div className="w-6 h-6 rounded-full bg-gotu-accent bg-opacity-20 flex items-center justify-center">
              <span className="text-xs text-gotu-accent font-bold">{user?.username?.[0]?.toUpperCase()}</span>
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-medium text-gotu-text truncate">{user?.username}</div>
              <div className="text-xs text-gotu-muted capitalize">{user?.role}</div>
            </div>
            <button onClick={handleLogout} className="text-gotu-muted hover:text-gotu-danger transition-colors" title="Logout">
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </aside>
      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
