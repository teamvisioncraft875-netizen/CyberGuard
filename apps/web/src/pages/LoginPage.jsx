import React, { useState } from 'react';
import { AuthLayout } from '../layouts/AuthLayout';
import { Input, Button } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { Mail, Lock, ArrowRight, AlertCircle } from 'lucide-react';

/**
 * Enterprise User Login Page
 * Connected to POST /api/v1/auth/login via authService / useAuth
 */
export function LoginPage({ onLoginSuccess, onNavigateSignup }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (!email.trim() || !password) {
      setErrorMessage('Please enter both email and password.');
      return;
    }

    setIsSubmitting(true);
    try {
      await login(email.trim(), password);
      onLoginSuccess?.();
    } catch (err) {
      if (err.status === 429 || err.code === 'RATE_LIMITED') {
        setErrorMessage(
          'Too many authentication attempts. Auth is rate-limited to 5 requests per 15 minutes. Please wait before retrying.'
        );
      } else {
        setErrorMessage(
          err.message || 'Authentication failed. Please verify your email and password.'
        );
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <AuthLayout
      title="Sign In"
      subtitle="Enter your enterprise credentials to access the CyberGuard security platform."
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {errorMessage && (
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-destructive text-xs flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="leading-relaxed">{errorMessage}</span>
          </div>
        )}

        <Input
          label="Email Address"
          type="email"
          placeholder="priya.sharma@bharatfintech.in"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          iconLeft={Mail}
          autoComplete="email"
          required
        />

        <Input
          label="Password"
          type="password"
          placeholder="Enter your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          iconLeft={Lock}
          autoComplete="current-password"
          required
        />

        <Button
          type="submit"
          variant="default"
          size="lg"
          className="w-full mt-2 font-medium text-xs font-mono tracking-wider uppercase"
          isLoading={isSubmitting}
          iconRight={ArrowRight}
        >
          Sign In
        </Button>

        <div className="text-center pt-2 text-xs text-muted-foreground">
          <span>Don&apos;t have an account? </span>
          <button
            type="button"
            onClick={onNavigateSignup}
            className="text-primary hover:underline font-medium"
          >
            Create account
          </button>
        </div>
      </form>
    </AuthLayout>
  );
}
