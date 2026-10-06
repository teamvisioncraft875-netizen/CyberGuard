import React, { useState } from 'react';
import { AuthLayout } from '../layouts/AuthLayout';
import { Input, Button } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { User, Mail, Lock, Building2, ArrowRight, AlertCircle } from 'lucide-react';

/**
 * Enterprise & Individual Account Registration Page
 * Connected to POST /api/v1/auth/signup via authService / useAuth
 */
export function SignupPage({ onSignupSuccess, onNavigateLogin }) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState('individual'); // 'individual' | 'employee'
  const [organizationName, setOrganizationName] = useState('');
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

    if (role === 'employee' && !organizationName.trim()) {
      setErrorMessage('Organization name is required for employee registration.');
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
      await signup(
        email.trim(),
        password,
        fullName.trim(),
        role,
        role === 'employee' ? organizationName.trim() : undefined
      );
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

        {/* Account Role Toggle */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-foreground">Account Type</label>
          <div className="grid grid-cols-2 gap-2 p-1 bg-muted/40 border border-border/40 rounded-lg">
            <button
              type="button"
              onClick={() => setRole('individual')}
              className={`py-1.5 px-3 rounded-md text-xs font-medium transition-all ${
                role === 'individual'
                  ? 'bg-background text-foreground shadow-sm border border-border/60'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Individual
            </button>
            <button
              type="button"
              onClick={() => setRole('employee')}
              className={`py-1.5 px-3 rounded-md text-xs font-medium transition-all ${
                role === 'employee'
                  ? 'bg-background text-foreground shadow-sm border border-border/60'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Enterprise / Employee
            </button>
          </div>
        </div>

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

        {role === 'employee' && (
          <Input
            label="Organization Name"
            type="text"
            placeholder="e.g. Acme Cyber Security Inc."
            value={organizationName}
            onChange={(e) => setOrganizationName(e.target.value)}
            iconLeft={Building2}
            autoComplete="organization"
            required
          />
        )}

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
