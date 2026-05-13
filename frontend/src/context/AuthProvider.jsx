import { useState, useCallback } from 'react';
import { getCurrentUser, login as apiLogin, updateCurrentUserProfile } from '../api';
import { AuthContext } from './AuthContext.js';

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(() => {
    const stored = localStorage.getItem('ais_current_user');
    if (stored) {
      try {
        return JSON.parse(stored);
      } catch {
        localStorage.removeItem('ais_current_user');
      }
    }
    const username = localStorage.getItem('ais_user');
    return username ? { username, role: '', profile: {}, session: {} } : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem('ais_token') || null);

  const persistUser = useCallback((nextUser) => {
    if (nextUser) {
      localStorage.setItem('ais_current_user', JSON.stringify(nextUser));
      localStorage.setItem('ais_user', nextUser.username || '');
    } else {
      localStorage.removeItem('ais_current_user');
      localStorage.removeItem('ais_user');
    }
    setCurrentUser(nextUser);
  }, []);

  const login = useCallback(async (username, password) => {
    const data = await apiLogin(username, password);
    const tok = data.token || data.access_token || 'authenticated';
    const nextUser = data.user || {
      username: data.username || username,
      role: data.role || '',
      profile: {},
      session: {},
    };
    localStorage.setItem('ais_token', tok);
    persistUser(nextUser);
    setToken(tok);
    return data;
  }, [persistUser]);

  const refreshCurrentUser = useCallback(async () => {
    const nextUser = await getCurrentUser();
    persistUser(nextUser);
    return nextUser;
  }, [persistUser]);

  const updateProfile = useCallback(async (profile) => {
    const nextUser = await updateCurrentUserProfile(profile);
    persistUser(nextUser);
    return nextUser;
  }, [persistUser]);

  const logout = useCallback(() => {
    localStorage.removeItem('ais_token');
    persistUser(null);
    setToken(null);
  }, [persistUser]);

  const user = currentUser?.username || null;

  return (
    <AuthContext.Provider value={{
      user,
      currentUser,
      token,
      isAuthenticated: !!token,
      login,
      logout,
      refreshCurrentUser,
      updateProfile,
    }}>
      {children}
    </AuthContext.Provider>
  );
}
