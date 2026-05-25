import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom';
import { useEffect, Component, Suspense, lazy } from 'react';
import { AuthProvider } from './context/AuthProvider';
import { AppProvider }  from './context/AppProvider';

const Layout = lazy(() => import('./components/Layout/Layout'));
const Login = lazy(() => import('./pages/Login'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const TrainDetect = lazy(() => import('./pages/TrainDetect'));
const Alerts = lazy(() => import('./pages/Alerts'));
const Settings = lazy(() => import('./pages/Settings'));
const Account = lazy(() => import('./pages/Account'));
const HelpCentre = lazy(() => import('./pages/HelpCentre'));
const Users = lazy(() => import('./pages/Users'));

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

function RouteFallback() {
  return (
    <div style={{minHeight:'100vh',display:'grid',placeItems:'center',background:'#191724',color:'#e0def4',fontFamily:'system-ui, sans-serif'}}>
      Loading...
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppProvider>
          <ErrorBoundary>
            <Suspense fallback={<RouteFallback />}>
              <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/" element={<Layout />}>
                  <Route index           element={<Dashboard />} />
                  <Route path="train"    element={<TrainDetect />} />
                  <Route path="alerts"   element={<Alerts />} />
                  <Route path="settings" element={<Settings />} />
                  <Route path="account"       element={<Account />} />
                  <Route path="users"         element={<Users />} />
                  <Route path="help-centre" element={<HelpCentre />} />
                </Route>
                <Route path="*" element={<CatchAll />} />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </AppProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
