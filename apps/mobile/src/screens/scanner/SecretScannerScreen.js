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
import { useTheme } from '../../context/ThemeContext';
import { AppHeader } from '../../components/AppHeader';
import { secretService } from '../../services/secretService';
import { CyberButton } from '../../components/CyberButton';

export function SecretScannerScreen({ navigation }) {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (loading) return;
    const trimmed = input.trim();
    if (!trimmed) {
      setError('Please enter or paste content to inspect for exposed secrets');
      return;
    }

    setError('');
    setLoading(true);

    const lineCount = trimmed.split('\n').length;

    try {
      // Dispatches real backend request to POST /api/v1/check/secret
      // Notice: candidate secret is NEVER logged or passed to analytics
      const result = await secretService.scanSecret(trimmed);

      // Clean in-memory input state immediately after scan completes
      setInput('');

      // Navigate to ScanResultScreen without passing sensitive content
      navigation.navigate('ScanResult', {
        result,
        scanType: 'Secret',
        targetSummary: `${lineCount} line${lineCount === 1 ? '' : 's'} analyzed`
      });
    } catch (err) {
      // Never log the secret in errors
      setError(err.message || 'Secret scan request failed. Please verify connection and retry.');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    if (loading) return;
    setInput('');
    setError('');
  };

  const lineCount = input ? input.split('\n').length : 0;
  const charCount = input.length;

  const { colors } = useTheme();

  return (
    <View style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <AppHeader title="Secret & Token Scanner" showBack={true} navigation={navigation} />
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.keyboardView}
      >

        <ScrollView
          contentContainerStyle={styles.content}
          keyboardShouldPersistTaps="handled"
        >
          {error ? (
            <View style={styles.errorBox} accessibilityRole="alert">
              <Text style={styles.errorText}>{error}</Text>
            </View>
          ) : null}

          {/* Form Card */}
          <View style={styles.card}>
            <View style={styles.textAreaHeader}>
              <Text style={styles.inputLabel}>PASTE CODE, CONFIG, OR TEXT</Text>
              {input.length > 0 && !loading && (
                <TouchableOpacity
                  onPress={handleClear}
                  accessibilityLabel="Clear input content"
                  accessibilityRole="button"
                >
                  <Text style={styles.clearText}>Clear</Text>
                </TouchableOpacity>
              )}
            </View>

            <TextInput
              style={styles.textArea}
              placeholder="e.g. AWS_ACCESS_KEY_ID=AKIA...&#10;DATABASE_URL=postgres://user:pass@host:5432/db&#10;-----BEGIN RSA PRIVATE KEY-----"
              placeholderTextColor={COLORS.textMuted}
              multiline
              numberOfLines={8}
              textAlignVertical="top"
              value={input}
              editable={!loading}
              onChangeText={(val) => {
                setInput(val);
                if (error) setError('');
              }}
              autoCapitalize="none"
              autoCorrect={false}
              spellCheck={false}
              accessibilityLabel="Content to scan for exposed secrets"
            />

            <View style={styles.counterRow}>
              <Text style={styles.counterText}>
                {charCount} character{charCount === 1 ? '' : 's'} • {lineCount} line{lineCount === 1 ? '' : 's'}
              </Text>
              <Text style={styles.rateLimitNote}>Rate limit: 20 scans / 15m</Text>
            </View>

            <CyberButton
              title={loading ? 'Analyzing Content...' : 'Inspect for Exposed Secrets'}
              onPress={handleScan}
              loading={loading}
              disabled={loading || !input.trim()}
              accessibilityLabel="Inspect for Exposed Secrets"
              style={styles.scanBtn}
            />
          </View>

          {/* Privacy Protocol Notice */}
          <View style={styles.privacyCard}>
            <Text style={styles.privacyTitle}>🔒 SENSITIVE DATA PRIVACY</Text>
            <Text style={styles.privacyText}>
              Content is analyzed in transient memory via secure HTTPS. Submitted credentials are never permanently stored, never saved in local app storage, never logged to device logs, and never included in navigation parameters.
            </Text>
          </View>

          {/* Detected Signatures Catalog */}
          <View style={styles.infoCard}>
            <Text style={styles.infoTitle}>DETECTED CREDENTIAL CATEGORIES</Text>
            <View style={styles.tagGrid}>
              <View style={styles.tagItem}>
                <Text style={styles.tagText}>AWS Access Keys & Secrets</Text>
              </View>
              <View style={styles.tagItem}>
                <Text style={styles.tagText}>Database Passwords & URIs</Text>
              </View>
              <View style={styles.tagItem}>
                <Text style={styles.tagText}>RSA & SSH Private Keys</Text>
              </View>
              <View style={styles.tagItem}>
                <Text style={styles.tagText}>GitHub, Stripe & Slack Tokens</Text>
              </View>
              <View style={styles.tagItem}>
                <Text style={styles.tagText}>JWT Secrets & Bearer Keys</Text>
              </View>
              <View style={styles.tagItem}>
                <Text style={styles.tagText}>High-Entropy Pseudorandom Tokens</Text>
              </View>
            </View>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
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
  header: {
    paddingHorizontal: 16,
    paddingTop: 8,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border
  },
  backBtn: {
    marginBottom: 6
  },
  backBtnText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  },
  title: {
    color: COLORS.textPrimary,
    fontSize: 22,
    fontWeight: '800'
  },
  subtitle: {
    color: COLORS.textMuted,
    fontSize: 13,
    marginTop: 2
  },
  content: {
    padding: 16,
    paddingBottom: 40
  },
  errorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.4)',
    borderRadius: 10,
    padding: 12,
    marginBottom: 16
  },
  errorText: {
    color: COLORS.critical,
    fontSize: 13,
    lineHeight: 18,
    fontWeight: '600'
  },
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 16
  },
  textAreaHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8
  },
  inputLabel: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1
  },
  clearText: {
    color: COLORS.primary,
    fontSize: 12,
    fontWeight: '700'
  },
  textArea: {
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 10,
    padding: 14,
    color: COLORS.textPrimary,
    fontSize: 13,
    minHeight: 140,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    lineHeight: 19
  },
  counterRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 8,
    marginBottom: 16
  },
  counterText: {
    color: COLORS.textMuted,
    fontSize: 11
  },
  rateLimitNote: {
    color: COLORS.textMuted,
    fontSize: 11
  },
  scanBtn: {
    marginTop: 4
  },
  privacyCard: {
    backgroundColor: 'rgba(0, 240, 255, 0.04)',
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.2)',
    marginBottom: 16
  },
  privacyTitle: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 6
  },
  privacyText: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 18
  },
  infoCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 16,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  infoTitle: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 12
  },
  tagGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8
  },
  tagItem: {
    backgroundColor: COLORS.surface,
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  tagText: {
    color: COLORS.textSecondary,
    fontSize: 11,
    fontWeight: '600'
  }
});
