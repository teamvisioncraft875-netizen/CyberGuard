import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  TouchableOpacity,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  SafeAreaView
} from 'react-native';
import { COLORS } from '../../constants/colors';
import { useAuth } from '../../hooks/useAuth';
import { CyberButton } from '../../components/CyberButton';

export function LoginScreen({ navigation }) {
  const { login, error, clearError } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState('');

  const handleLogin = async () => {
    if (!email.trim() || !password) {
      setFormError('Please enter both email and password');
      return;
    }
    setFormError('');
    clearError();
    setLoading(true);

    try {
      await login(email.trim(), password);
    } catch (err) {
      setFormError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.safeArea}>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.keyboardView}
      >
        <ScrollView
          contentContainerStyle={styles.scrollContent}
          keyboardShouldPersistTaps="handled"
        >
          {/* Brand Header */}
          <View style={styles.brandContainer}>
            <View style={styles.logoBadge}>
              <Text style={styles.logoIcon}>🛡️</Text>
            </View>
            <Text style={styles.appName}>CYBERGUARD</Text>
            <Text style={styles.appTagline}>Personal & Enterprise Threat Defense</Text>
          </View>

          {/* Form Card */}
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Sign In</Text>
            <Text style={styles.cardSubtitle}>
              Authenticate with your credentials to access live incident monitoring
            </Text>

            {(formError || error) ? (
              <View style={styles.errorBox}>
                <Text style={styles.errorText}>{formError || error}</Text>
              </View>
            ) : null}

            {/* Email Field */}
            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>EMAIL ADDRESS</Text>
              <TextInput
                style={styles.input}
                placeholder="name@organization.com"
                placeholderTextColor={COLORS.textMuted}
                autoCapitalize="none"
                keyboardType="email-address"
                autoCorrect={false}
                value={email}
                onChangeText={(text) => {
                  setEmail(text);
                  if (formError) setFormError('');
                }}
              />
            </View>

            {/* Password Field */}
            <View style={styles.inputGroup}>
              <View style={styles.passwordHeader}>
                <Text style={styles.inputLabel}>PASSWORD</Text>
                <TouchableOpacity onPress={() => setShowPassword(!showPassword)}>
                  <Text style={styles.toggleText}>
                    {showPassword ? 'Hide' : 'Show'}
                  </Text>
                </TouchableOpacity>
              </View>
              <TextInput
                style={styles.input}
                placeholder="••••••••••••"
                placeholderTextColor={COLORS.textMuted}
                secureTextEntry={!showPassword}
                autoCapitalize="none"
                value={password}
                onChangeText={(text) => {
                  setPassword(text);
                  if (formError) setFormError('');
                }}
              />
            </View>

            {/* Submit Button */}
            <CyberButton
              title="Authenticate Securely"
              onPress={handleLogin}
              loading={loading}
              style={styles.submitBtn}
            />

            {/* Signup Link */}
            <View style={styles.footerRow}>
              <Text style={styles.footerText}>New to CyberGuard? </Text>
              <TouchableOpacity onPress={() => navigation.navigate('Signup')}>
                <Text style={styles.signupLink}>Create an account</Text>
              </TouchableOpacity>
            </View>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.background
  },
  keyboardView: {
    flex: 1
  },
  scrollContent: {
    flexGrow: 1,
    justifyContent: 'center',
    padding: 20
  },
  brandContainer: {
    alignItems: 'center',
    marginBottom: 24
  },
  logoBadge: {
    width: 60,
    height: 60,
    borderRadius: 16,
    backgroundColor: COLORS.card,
    borderWidth: 1.5,
    borderColor: COLORS.primary,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 12
  },
  logoIcon: {
    fontSize: 28
  },
  appName: {
    color: COLORS.primary,
    fontSize: 24,
    fontWeight: '900',
    letterSpacing: 2
  },
  appTagline: {
    color: COLORS.textSecondary,
    fontSize: 13,
    marginTop: 4,
    fontWeight: '500'
  },
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 16,
    padding: 22,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  cardTitle: {
    color: COLORS.textPrimary,
    fontSize: 20,
    fontWeight: '800',
    marginBottom: 4
  },
  cardSubtitle: {
    color: COLORS.textSecondary,
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 18
  },
  errorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.12)',
    borderLeftWidth: 4,
    borderLeftColor: COLORS.danger,
    padding: 10,
    borderRadius: 6,
    marginBottom: 14
  },
  errorText: {
    color: COLORS.danger,
    fontSize: 12,
    fontWeight: '600'
  },
  inputGroup: {
    marginBottom: 16
  },
  inputLabel: {
    color: COLORS.textSecondary,
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.8,
    marginBottom: 6
  },
  passwordHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  toggleText: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '600'
  },
  input: {
    backgroundColor: COLORS.background,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 8,
    paddingHorizontal: 14,
    paddingVertical: 12,
    color: COLORS.textPrimary,
    fontSize: 14
  },
  submitBtn: {
    marginTop: 6,
    marginBottom: 16
  },
  footerRow: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center'
  },
  footerText: {
    color: COLORS.textMuted,
    fontSize: 13
  },
  signupLink: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  }
});
