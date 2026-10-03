import React, { useState } from 'react';
import { AuthLayout } from '../layouts/AuthLayout';
import { Input, Button } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { User, Mail, Lock, ArrowRight, AlertCircle } from 'lucide-react';

/**
 * Enterprise Account Registration Page
 * Connected to POST /api/v1/auth/signup via authService / useAuth
 */
export function SignupPage({ onSignupSuccess, onNavigateLogin }) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { signup } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (!fullName.trim() || !email.trim() || !password) {
      setErrorMessage('Please complete all required fields.');
      return;
    }

    if (password.length < 6) {
      setErrorMessage('Password must be at least 6 characters.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match.');
      return;
    }

    setIsSubmitting(true);
    try {
      await signup(email.trim(), password, fullName.trim(), 'individual');
      onSignupSuccess?.();
    } catch (err) {
      if (err.status === 429 || err.code === 'RATE_LIMITED') {
        setErrorMessage(
          'Too many registration attempts. Auth is rate-limited to 5 requests per 15 minutes. Please wait before retrying.'
        );
      } else {
        setErrorMessage(
          err.message || 'Registration failed. Please check your information and try again.'
        );
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <AuthLayout
      title="Create Account"
      subtitle="Register an enterprise user profile to start protecting communications and endpoints."
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {errorMessage && (
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-destructive text-xs flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="leading-relaxed">{errorMessage}</span>
          </div>
        )}

        <Input
          label="Full Name"
          type="text"
          placeholder="Jane Doe"
          value={fullName}
          onChange={(e) => setFullName(e.target.value)}
          iconLeft={User}
          autoComplete="name"
          required
        />

        <Input
          label="Email Address"
          type="email"
          placeholder="analyst@cyberguard.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          iconLeft={Mail}
          autoComplete="email"
          required
        />

        <Input
          label="Password"
          type="password"
          placeholder="Minimum 6 characters"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          iconLeft={Lock}
          autoComplete="new-password"
          required
        />

        <Input
          label="Confirm Password"
          type="password"
          placeholder="Re-enter password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          iconLeft={Lock}
          autoComplete="new-password"
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
          Create Account
        </Button>

        <div className="text-center pt-2 text-xs text-muted-foreground">
          <span>Already have an account? </span>
          <button
            type="button"
            onClick={onNavigateLogin}
            className="text-primary hover:underline font-medium"
          >
            Sign in
          </button>
        </div>
      </form>
    </AuthLayout>
  );
}
