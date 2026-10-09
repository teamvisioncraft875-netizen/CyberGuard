import React, { useState, useEffect } from 'react';
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
import { getEffectiveApiUrl, setCustomApiUrl } from '../../services/apiClient';
import { CONFIG } from '../../constants/config';

export function LoginScreen({ navigation }) {
  const { login, error, clearError } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState('');

  // Server Endpoint Configuration State
  const [serverUrl, setServerUrl] = useState('');
  const [showServerConfig, setShowServerConfig] = useState(false);
  const [serverTestStatus, setServerTestStatus] = useState(null);
  const [testingServer, setTestingServer] = useState(false);

  useEffect(() => {
    getEffectiveApiUrl().then((url) => {
      setServerUrl(url);
    });
  }, []);

  const handleTestConnection = async (target) => {
    const raw = (target || serverUrl || '').trim();
    if (!raw) {
      setServerTestStatus({ ok: false, message: 'Please enter a valid server URL' });
      return;
    }
    setTestingServer(true);
    setServerTestStatus(null);
    try {
      const clean = raw.replace(/\/+$/, '');
      const healthUrl = clean.includes('/api/v1') ? `${clean}/health` : `${clean}/api/v1/health`;
      const res = await fetch(healthUrl, { method: 'GET' });
      if (res.ok) {
        setServerTestStatus({ ok: true, message: 'Connected to CYBERGUARD Backend!' });
      } else {
        setServerTestStatus({ ok: false, message: `Server replied with HTTP ${res.status}` });
      }
    } catch (err) {
      setServerTestStatus({
        ok: false,
        message: `Connection failed: ${err.message}. Ensure PC and phone are on the same Wi-Fi.`
      });
    } finally {
      setTestingServer(false);
    }
  };

  const handleSaveServerUrl = async () => {
    try {
      const saved = await setCustomApiUrl(serverUrl);
      setServerUrl(saved);
      await handleTestConnection(saved);
    } catch (err) {
      setServerTestStatus({ ok: false, message: `Failed to save: ${err.message}` });
    }
  };

  const handleResetServerUrl = async () => {
    await setCustomApiUrl(null);
    setServerUrl(CONFIG.API_URL);
    setServerTestStatus(null);
  };

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
      const msg = err.message || 'Authentication failed';
      if (msg.toLowerCase().includes('network request failed')) {
        setFormError('Network request failed: Could not reach backend server. Tap "Server Settings" below to adjust the IP.');
        setShowServerConfig(true);
      } else {
        setFormError(msg);
      }
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

            {/* Server Settings Link/Panel */}
            <View style={styles.serverSection}>
              <TouchableOpacity
                style={styles.serverToggleBtn}
                onPress={() => setShowServerConfig(!showServerConfig)}
              >
                <Text style={styles.serverToggleText}>
                  ⚙️ {showServerConfig ? 'Hide Server Configuration' : 'Server Connection Settings'}
                </Text>
              </TouchableOpacity>

              {showServerConfig && (
                <View style={styles.serverCard}>
                  <Text style={styles.serverCardTitle}>API BACKEND ADDRESS</Text>
                  <Text style={styles.serverCardHint}>
                    Change IP if backend runs on a different host/network
                  </Text>
                  <TextInput
                    style={styles.serverInput}
                    placeholder="http://192.168.1.21:5000/api/v1"
                    placeholderTextColor={COLORS.textMuted}
                    autoCapitalize="none"
                    autoCorrect={false}
                    value={serverUrl}
                    onChangeText={setServerUrl}
                  />

                  {serverTestStatus && (
                    <View
                      style={[
                        styles.serverStatusBanner,
                        serverTestStatus.ok ? styles.serverStatusSuccess : styles.serverStatusError
                      ]}
                    >
                      <Text
                        style={[
                          styles.serverStatusText,
                          serverTestStatus.ok ? styles.serverStatusTextSuccess : styles.serverStatusTextError
                        ]}
                      >
                        {serverTestStatus.ok ? '✓ ' : '⚠ '} {serverTestStatus.message}
                      </Text>
                    </View>
                  )}

                  <View style={styles.serverButtonRow}>
                    <TouchableOpacity
                      style={[styles.smallBtn, styles.testBtn]}
                      onPress={() => handleTestConnection(serverUrl)}
                      disabled={testingServer}
                    >
                      <Text style={styles.smallBtnText}>
                        {testingServer ? 'Testing...' : 'Test'}
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.smallBtn, styles.saveBtn]}
                      onPress={handleSaveServerUrl}
                    >
                      <Text style={styles.smallBtnText}>Save</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.smallBtn, styles.resetBtn]}
                      onPress={handleResetServerUrl}
                    >
                      <Text style={[styles.smallBtnText, styles.resetBtnText]}>Reset</Text>
                    </TouchableOpacity>
                  </View>
                </View>
              )}
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
  },
  serverSection: {
    marginTop: 20,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
    paddingTop: 16
  },
  serverToggleBtn: {
    alignItems: 'center',
    paddingVertical: 6
  },
  serverToggleText: {
    color: COLORS.textMuted,
    fontSize: 12,
    fontWeight: '600'
  },
  serverCard: {
    marginTop: 12,
    backgroundColor: 'rgba(255, 255, 255, 0.03)',
    borderRadius: 8,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 12
  },
  serverCardTitle: {
    color: COLORS.textSecondary,
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 0.8,
    marginBottom: 4
  },
  serverCardHint: {
    color: COLORS.textMuted,
    fontSize: 11,
    marginBottom: 10
  },
  serverInput: {
    backgroundColor: COLORS.background,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 6,
    paddingHorizontal: 12,
    paddingVertical: 8,
    color: COLORS.textPrimary,
    fontSize: 13,
    marginBottom: 10
  },
  serverStatusBanner: {
    padding: 8,
    borderRadius: 6,
    marginBottom: 10
  },
  serverStatusSuccess: {
    backgroundColor: 'rgba(34, 197, 94, 0.15)',
    borderLeftWidth: 3,
    borderLeftColor: '#22c55e'
  },
  serverStatusError: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderLeftWidth: 3,
    borderLeftColor: COLORS.danger
  },
  serverStatusText: {
    fontSize: 11,
    fontWeight: '600'
  },
  serverStatusTextSuccess: {
    color: '#22c55e'
  },
  serverStatusTextError: {
    color: COLORS.danger
  },
  serverButtonRow: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
    gap: 8
  },
  smallBtn: {
    paddingVertical: 7,
    paddingHorizontal: 14,
    borderRadius: 6,
    alignItems: 'center',
    justifyContent: 'center'
  },
  testBtn: {
    backgroundColor: COLORS.card,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  saveBtn: {
    backgroundColor: COLORS.primary
  },
  resetBtn: {
    backgroundColor: 'transparent'
  },
  smallBtnText: {
    color: '#ffffff',
    fontSize: 12,
    fontWeight: '600'
  },
  resetBtnText: {
    color: COLORS.textMuted
  }
});
