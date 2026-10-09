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
import { scannerService } from '../../services/scannerService';
import { CyberButton } from '../../components/CyberButton';

export function UrlScannerScreen({ navigation }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (loading) return;
    if (!url.trim()) {
      setError('Please enter a website address or URL to scan');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const result = await scannerService.scanUrl(url.trim());
      navigation.navigate('ScanResult', {
        result,
        scanType: 'URL',
        targetSummary: url.trim()
      });
    } catch (err) {
      console.warn('[UrlScannerScreen.handleScan]', err.message);
      setError(err.message || 'URL scan request failed. Please check your connection and retry.');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    if (loading) return;
    setUrl('');
    setError('');
  };

  const { colors } = useTheme();

  return (
    <View style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <AppHeader title="URL Threat Scanner" showBack={true} navigation={navigation} />
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.keyboardView}
      >

        <ScrollView
          contentContainerStyle={styles.content}
          keyboardShouldPersistTaps="handled"
        >
          {error ? (
            <View style={styles.errorBox}>
              <Text style={styles.errorText}>{error}</Text>
            </View>
          ) : null}

          {/* Form Card */}
          <View style={styles.card}>
            <Text style={styles.inputLabel}>ENTER WEB ADDRESS / LINK</Text>
            <View style={styles.inputWrapper}>
              <TextInput
                style={styles.input}
                placeholder="https://example-bank-login.com"
                placeholderTextColor={COLORS.textMuted}
                autoCapitalize="none"
                autoCorrect={false}
                keyboardType="url"
                value={url}
                editable={!loading}
                onChangeText={(text) => {
                  setUrl(text);
                  if (error) setError('');
                }}
              />
              {url.length > 0 && !loading && (
                <TouchableOpacity onPress={handleClear} style={styles.clearBtn}>
                  <Text style={styles.clearBtnText}>✕</Text>
                </TouchableOpacity>
              )}
            </View>

            <Text style={styles.inputHint}>
              Supports full URLs (e.g., https://...) and raw domain paths. Protocol is automatically resolved.
            </Text>

            <View style={styles.buttonRow}>
              <CyberButton
                title={loading ? 'Scanning Threat Vectors...' : 'Analyze URL'}
                onPress={handleScan}
                loading={loading}
                disabled={loading || !url.trim()}
                style={styles.scanBtn}
              />
              {url.length > 0 && !loading && (
                <TouchableOpacity
                  style={styles.resetBtn}
                  onPress={handleClear}
                >
                  <Text style={styles.resetBtnText}>Clear</Text>
                </TouchableOpacity>
              )}
            </View>
          </View>

          {/* Real Backend Detection Capabilities */}
          <View style={styles.infoCard}>
            <Text style={styles.infoTitle}>HEURISTIC & ML DETECTIONS</Text>
            <View style={styles.bulletRow}>
              <Text style={styles.bullet}>•</Text>
              <Text style={styles.bulletText}>
                Shannon entropy & structural lexical anomaly evaluation
              </Text>
            </View>
            <View style={styles.bulletRow}>
              <Text style={styles.bullet}>•</Text>
              <Text style={styles.bulletText}>
                Brand impersonation targeting major enterprise institutions
              </Text>
            </View>
            <View style={styles.bulletRow}>
              <Text style={styles.bullet}>•</Text>
              <Text style={styles.bulletText}>
                Credential harvesting keyword matching & raw IP hostname detection
              </Text>
            </View>
            <View style={styles.bulletRow}>
              <Text style={styles.bullet}>•</Text>
              <Text style={styles.bulletText}>
                High-risk Top-Level Domain (TLD) classification
              </Text>
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
    paddingBottom: 32
  },
  errorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.12)',
    borderLeftWidth: 4,
    borderLeftColor: COLORS.danger,
    padding: 12,
    borderRadius: 8,
    marginBottom: 16
  },
  errorText: {
    color: COLORS.danger,
    fontSize: 13,
    lineHeight: 18,
    fontWeight: '600'
  },
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 16,
    padding: 18,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 16
  },
  inputLabel: {
    color: COLORS.textSecondary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 0.8,
    marginBottom: 8
  },
  inputWrapper: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.background,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 10,
    marginBottom: 8
  },
  input: {
    flex: 1,
    paddingHorizontal: 14,
    paddingVertical: 12,
    color: COLORS.textPrimary,
    fontSize: 14
  },
  clearBtn: {
    paddingHorizontal: 12,
    paddingVertical: 10
  },
  clearBtnText: {
    color: COLORS.textMuted,
    fontSize: 16,
    fontWeight: '700'
  },
  inputHint: {
    color: COLORS.textMuted,
    fontSize: 11,
    lineHeight: 16,
    marginBottom: 18
  },
  buttonRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10
  },
  scanBtn: {
    flex: 1
  },
  resetBtn: {
    paddingHorizontal: 16,
    height: 48,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: COLORS.surface,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  resetBtnText: {
    color: COLORS.textSecondary,
    fontSize: 13,
    fontWeight: '700'
  },
  infoCard: {
    backgroundColor: COLORS.cardSecondary,
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  infoTitle: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.8,
    marginBottom: 10
  },
  bulletRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: 8
  },
  bullet: {
    color: COLORS.primary,
    fontSize: 14,
    marginRight: 8,
    lineHeight: 18
  },
  bulletText: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 18,
    flex: 1
  }
});
