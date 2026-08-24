import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/AuthContext';
import styles from './Login.module.css';

/**
 * Login page — renders outside the App layout shell.
 * Full-viewport dark background with a centered credentials card.
 */
export default function Login() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const usernameRef = useRef<HTMLInputElement>(null);

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  // Auto-focus username input on mount
  useEffect(() => {
    usernameRef.current?.focus();
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className={styles.page}>
      <form className={styles.card} onSubmit={handleSubmit}>
        <div className={styles.logo}>Threat2Signal</div>
        <div className={styles.subtitle}>CTI Dashboard</div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="login-username">USERNAME</label>
          <input
            id="login-username"
            ref={usernameRef}
            type="text"
            className={styles.input}
            placeholder="Enter username"
            autoComplete="username"
            value={username}
            onChange={(e) => {
              setUsername(e.target.value);
              setError(null);
            }}
          />
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="login-password">PASSWORD</label>
          <input
            id="login-password"
            type="password"
            className={styles.input}
            placeholder="Enter password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setError(null);
            }}
          />
        </div>

        <button
          type="submit"
          className={styles.button}
          disabled={loading}
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>

        {error && <div className={styles.error} role="alert">{error}</div>}
      </form>
    </div>
  );
}
