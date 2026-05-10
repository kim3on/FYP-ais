import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom';
import { useEffect, Component } from 'react';
import { AuthProvider } from './context/AuthProvider';
import { AppProvider }  from './context/AppProvider';
import Layout      from './components/Layout/Layout';
import Login       from './pages/Login';
import Dashboard   from './pages/Dashboard';
import TrainDetect from './pages/TrainDetect';
import Alerts      from './pages/Alerts';
import Settings    from './pages/Settings';
import Account       from './pages/Account';
import Accessibility from './pages/Accessibility';

function CatchAll() {
  const navigate = useNavigate();
  useEffect(() => { navigate('/', { replace: true }); }, [navigate]);
  return null;
}

class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div style={{padding:'40px',fontFamily:'monospace',color:'#eb6f92',background:'#191724',minHeight:'100vh'}}>
          <h2>⚠ Runtime Error</h2>
          <pre style={{whiteSpace:'pre-wrap',color:'#e0def4',marginTop:'16px'}}>{this.state.error.message}</pre>
          <pre style={{whiteSpace:'pre-wrap',color:'#6e6a86',marginTop:'8px',fontSize:'12px'}}>{this.state.error.stack}</pre>
          <button onClick={() => this.setState({ error: null })} style={{marginTop:'16px',padding:'8px 16px',cursor:'pointer'}}>Retry</button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppProvider>
          <ErrorBoundary>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/" element={<Layout />}>
                <Route index           element={<Dashboard />} />
                <Route path="train"    element={<TrainDetect />} />
                <Route path="alerts"   element={<Alerts />} />
                <Route path="settings" element={<Settings />} />
                <Route path="account"       element={<Account />} />
                <Route path="accessibility" element={<Accessibility />} />
              </Route>
              <Route path="*" element={<CatchAll />} />
            </Routes>
          </ErrorBoundary>
        </AppProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
