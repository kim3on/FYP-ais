import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import './Login.css';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) navigate('/', { replace: true });
  }, [isAuthenticated, navigate]);

  if (isAuthenticated) return null;

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-bg">
      {/* Decorative blobs */}
      <div className="login-blob blob-1" />
      <div className="login-blob blob-2" />

      <div className="login-card fade-in">
        {/* Header */}
        <div className="login-header">
          <div className="login-icon">🛡</div>
          <h1 className="login-title">AIS-Detect</h1>
          <p className="login-sub">Artificial Immune System · Network IDS</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="login-form">
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="admin"
              autoComplete="username"
              required
            />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <div className="login-error">
              <span>⚠</span> {error}
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary login-btn"
            disabled={loading}
          >
            {loading ? <span className="spinner" /> : null}
            {loading ? 'Authenticating…' : 'Sign In'}
          </button>
        </form>

        <p className="login-footer">
          Authorised personnel only · Access is logged
        </p>
      </div>
    </div>
  );
}
