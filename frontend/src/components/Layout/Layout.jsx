import { Outlet, useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { useApp } from '../../hooks/useApp';
import Sidebar from './Sidebar';
import iiumAcknowledgement from '../../assets/IIUM_TAWHIDIC_UMMATIC_KHALIFAH.png';
import './Layout.css';

export default function Layout() {
  const { isAuthenticated } = useAuth();
  const { systemStatus } = useApp();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const navigate = useNavigate();
  const year = new Date().getFullYear();

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
        <footer className="app-footer">
          <div className="app-footer-logo">
            <img src={iiumAcknowledgement} alt="International Islamic University Malaysia acknowledgement" />
          </div>
          <div className="app-footer-project">
            <span>Project ID: 1627 D</span>
            <strong>Web-Based Network Anomaly Detection Using Artificial Immune Systems (AIS) and Unsupervised Learning</strong>
            <small>By Muhammad Iman Hakimi bin Muhamar Yazil (2218147) and Aiman Hafidz bin Aznan (2218565)</small>
            <small>Supervised by Dr. Amir 'Aatieff Bin Amir Hussin</small>
          </div>
          <div className="app-footer-meta">
            <span>CSCI 4402 Final Year Project II</span>
            <span>International Islamic University Malaysia</span>
            <span>v4.0.0 · {year}</span>
          </div>
        </footer>
      </main>
    </div>
  );
}
