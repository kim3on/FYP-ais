import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthProvider';
import { AppProvider }  from './context/AppProvider';
import Layout      from './components/Layout/Layout';
import Login       from './pages/Login';
import Dashboard   from './pages/Dashboard';
import TrainDetect from './pages/TrainDetect';
import Alerts      from './pages/Alerts';
import Settings    from './pages/Settings';
import Account     from './pages/Account';

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<Layout />}>
              <Route index           element={<Dashboard />} />
              <Route path="train"    element={<TrainDetect />} />
              <Route path="alerts"   element={<Alerts />} />
              <Route path="settings" element={<Settings />} />
              <Route path="account"  element={<Account />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AppProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
