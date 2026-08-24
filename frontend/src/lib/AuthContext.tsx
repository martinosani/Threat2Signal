import { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type { ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { setAuthToken } from './api';

interface AuthUser {
  username: string;
  role: string;
}

interface AuthContextValue {
  token: string | null;
  user: AuthUser | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const TOKEN_KEY = 'threat2signal_auth_token';
const USER_KEY = 'threat2signal_auth_user';

function decodeBase64Url(s: string): string {
  return atob(s.replace(/-/g, '+').replace(/_/g, '/'));
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  const [token, setToken] = useState<string | null>(() => {
    try {
      const stored = localStorage.getItem(TOKEN_KEY);
      if (!stored) return null;
      const payload = JSON.parse(decodeBase64Url(stored.split('.')[1]));
      if (payload.exp * 1000 > Date.now()) {
        setAuthToken(stored);
        return stored;
      }
    } catch {
      // malformed token
    }
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    return null;
  });

  const [user, setUser] = useState<AuthUser | null>(() => {
    if (!token) return null;
    try {
      const stored = localStorage.getItem(USER_KEY);
      return stored ? (JSON.parse(stored) as AuthUser) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    setAuthToken(token);
  }, [token]);

  const login = useCallback(async (username: string, password: string) => {
    let response: Response;
    try {
      response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
    } catch {
      throw new Error('Unable to reach the server');
    }

    if (response.status === 401) {
      throw new Error('Invalid username or password');
    }
    if (!response.ok) {
      throw new Error('Server error');
    }

    const data = (await response.json()) as { token: string; user: AuthUser };
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    setToken(data.token);
    setUser(data.user);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setToken(null);
    setUser(null);
    setAuthToken(null);
    queryClient.clear();
  }, [queryClient]);

  return (
    <AuthContext.Provider
      value={{ token, user, login, logout, isAuthenticated: token !== null }}
    >
      {children}
    </AuthContext.Provider>
  );
}
