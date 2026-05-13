import { Outlet, useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { useApp } from '../../hooks/useApp';
import Sidebar from './Sidebar';
import './Layout.css';

export default function Layout() {
  const { isAuthenticated } = useAuth();
  const { systemStatus } = useApp();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated) navigate('/login', { replace: true });
  }, [isAuthenticated, navigate]);

  if (!isAuthenticated) return null;

  const isReady = systemStatus?.models_ready;

  return (
    <div className={`app-layout ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
      <Sidebar isOpen={sidebarOpen} onToggle={() => setSidebarOpen((open) => !open)} />
      <main className="main-content">
        <div className="top-status-bar">
          <div className="status-item">
            <span className={`status-dot ${isReady ? 'online' : 'warning'}`} />
            <span className={`status-text ${isReady ? 't-success' : 't-warning'}`}>
              System Status : {isReady ? 'ACTIVE' : 'INACTIVE'}
            </span>
          </div>
          <div className="status-item">
            <span className={`status-dot ${isReady ? 'online' : 'warning'}`} />
            <span className={`status-text ${isReady ? 't-success' : 't-warning'}`}>
              {isReady ? (systemStatus.active_model || 'NSA').toUpperCase() : 'NO MODEL'}
            </span>
          </div>
        </div>
        <Outlet />
      </main>
    </div>
  );
}
