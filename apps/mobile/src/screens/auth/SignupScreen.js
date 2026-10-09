import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  TouchableOpacity,
  KeyboardAvoidingView,
  Platform,
  ScrollView
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { COLORS } from '../../constants/colors';
import { useAuth } from '../../hooks/useAuth';
import { useTheme } from '../../context/ThemeContext';
import { CyberButton } from '../../components/CyberButton';
import { CyberLogo } from '../../components/CyberLogo';
import { ThemeToggle } from '../../components/ThemeToggle';

export function SignupScreen({ navigation }) {
  const { colors } = useTheme();
  const { signup, error, clearError } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('individual'); // 'individual' or 'employee'
  const [organizationName, setOrganizationName] = useState('');
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState('');

  const handleSignup = async () => {
    if (!email.trim() || !password) {
      setFormError('Please enter email and password');
      return;
    }
    if (password.length < 8) {
      setFormError('Password must be at least 8 characters long');
      return;
    }
    if (role === 'employee' && !organizationName.trim()) {
      setFormError('Organization name is required for employee accounts');
      return;
    }

    setFormError('');
    clearError();
    setLoading(true);

    try {
      await signup(
        email.trim(),
        password,
        role,
        role === 'employee' ? organizationName.trim() : ''
      );
    } catch (err) {
      setFormError(err.message || 'Registration failed');
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
          {/* Brand & Theme Header */}
          <View style={styles.topBar}>
            <CyberLogo size={36} showText={true} />
            <ThemeToggle />
          </View>

          {/* Form Card */}
          <View style={[styles.card, { backgroundColor: colors.card, borderColor: colors.border }]}>
            <Text style={[styles.cardTitle, { color: colors.textPrimary }]}>Create Account</Text>
            <Text style={[styles.cardSubtitle, { color: colors.textSecondary }]}>
              Join the CyberGuard Enterprise Defense Network
            </Text>
            {(formError || error) ? (
              <View style={styles.errorBox}>
                <Text style={styles.errorText}>{formError || error}</Text>
              </View>
            ) : null}

            {/* Role Selection */}
            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>ACCOUNT TYPE</Text>
              <View style={styles.roleSelector}>
                <TouchableOpacity
                  style={[
                    styles.roleBtn,
                    role === 'individual' && styles.roleBtnActive
                  ]}
                  onPress={() => setRole('individual')}
                >
                  <Text
                    style={[
                      styles.roleBtnText,
                      role === 'individual' && styles.roleBtnTextActive
                    ]}
                  >
                    Individual / Family
                  </Text>
                </TouchableOpacity>

                <TouchableOpacity
                  style={[
                    styles.roleBtn,
                    role === 'employee' && styles.roleBtnActive
                  ]}
                  onPress={() => setRole('employee')}
                >
                  <Text
                    style={[
                      styles.roleBtnText,
                      role === 'employee' && styles.roleBtnTextActive
                    ]}
                  >
                    Enterprise Employee
                  </Text>
                </TouchableOpacity>
              </View>
            </View>

            {/* Email Field */}
            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>EMAIL ADDRESS</Text>
              <TextInput
                style={styles.input}
                placeholder="user@example.com"
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

            {/* Organization Name (if employee) */}
            {role === 'employee' && (
              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>ORGANIZATION NAME</Text>
                <TextInput
                  style={styles.input}
                  placeholder="Acme Cyber Corp"
                  placeholderTextColor={COLORS.textMuted}
                  value={organizationName}
                  onChangeText={(text) => {
                    setOrganizationName(text);
                    if (formError) setFormError('');
                  }}
                />
              </View>
            )}

            {/* Password Field */}
            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>PASSWORD (MIN 8 CHARS)</Text>
              <TextInput
                style={styles.input}
                placeholder="••••••••••••"
                placeholderTextColor={COLORS.textMuted}
                secureTextEntry
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
              title="Register & Activate Guard"
              onPress={handleSignup}
              loading={loading}
              style={styles.submitBtn}
            />

            {/* Login Link */}
            <View style={styles.footerRow}>
              <Text style={styles.footerText}>Already registered? </Text>
              <TouchableOpacity onPress={() => navigation.navigate('Login')}>
                <Text style={styles.loginLink}>Sign in</Text>
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
  topBar: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
    paddingHorizontal: 4
  },
  brandContainer: {
    alignItems: 'center',
    marginBottom: 20
  },
  logoBadge: {
    width: 52,
    height: 52,
    borderRadius: 14,
    backgroundColor: COLORS.card,
    borderWidth: 1.5,
    borderColor: COLORS.primary,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 10
  },
  logoIcon: {
    fontSize: 24
  },
  appName: {
    color: COLORS.primary,
    fontSize: 22,
    fontWeight: '950',
    letterSpacing: 1.5
  },
  appTagline: {
    color: COLORS.textSecondary,
    fontSize: 12,
    marginTop: 4
  },
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 16,
    padding: 22,
    borderWidth: 1,
    borderColor: COLORS.border
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
  roleSelector: {
    flexDirection: 'row',
    backgroundColor: COLORS.background,
    borderRadius: 8,
    padding: 3,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  roleBtn: {
    flex: 1,
    paddingVertical: 9,
    alignItems: 'center',
    borderRadius: 6
  },
  roleBtnActive: {
    backgroundColor: COLORS.surface
  },
  roleBtnText: {
    color: COLORS.textMuted,
    fontSize: 12,
    fontWeight: '600'
  },
  roleBtnTextActive: {
    color: COLORS.primary,
    fontWeight: '800'
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
    marginTop: 8,
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
  loginLink: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  }
});
