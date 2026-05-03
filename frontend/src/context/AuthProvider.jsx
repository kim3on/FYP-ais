import { useState, useCallback } from 'react';
import { login as apiLogin } from '../api';
import { AuthContext } from './AuthContext.js';

export function AuthProvider({ children }) {
  const [user, setUser]   = useState(() => localStorage.getItem('ais_user') || null);
  const [token, setToken] = useState(() => localStorage.getItem('ais_token') || null);

  const login = useCallback(async (username, password) => {
    const data = await apiLogin(username, password);
    const tok = data.token || data.access_token || 'authenticated';
    localStorage.setItem('ais_token', tok);
    localStorage.setItem('ais_user', username);
    setToken(tok);
    setUser(username);
    return data;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('ais_token');
    localStorage.removeItem('ais_user');
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: !!token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
