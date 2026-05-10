import { Outlet, useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { useApp } from '../../hooks/useApp';
import Sidebar from './Sidebar';
import './Layout.css';

export default function Layout() {
  const { isAuthenticated } = useAuth();
  const { systemStatus } = useApp();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated) navigate('/login', { replace: true });
  }, [isAuthenticated, navigate]);

  if (!isAuthenticated) return null;

  const isReady = systemStatus?.models_ready;

  return (
    <div className="app-layout">
      <Sidebar />
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
