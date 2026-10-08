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
import { scannerService } from '../../services/scannerService';
import { CyberButton } from '../../components/CyberButton';

const SOURCE_TYPES = [
  { id: 'sms', label: 'SMS / Text', icon: '📱' },
  { id: 'email', label: 'Email', icon: '✉️' },
  { id: 'social', label: 'Social Media', icon: '💬' }
];

export function MessageScannerScreen({ navigation }) {
  const [text, setText] = useState('');
  const [sourceType, setSourceType] = useState('sms');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (loading) return;
    if (!text.trim()) {
      setError('Please enter or paste the message text to analyze');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const result = await scannerService.scanMessage(text.trim(), sourceType);
      navigation.navigate('ScanResult', {
        result,
        scanType: 'Message',
        targetSummary: `${sourceType.toUpperCase()} Message`
      });
    } catch (err) {
      console.warn('[MessageScannerScreen.handleScan]', err.message);
      setError(err.message || 'Message scan request failed. Please check your connection and retry.');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    if (loading) return;
    setText('');
    setError('');
  };

  return (
    <SafeAreaView style={styles.safeArea}>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.keyboardView}
      >
        <View style={styles.header}>
          <TouchableOpacity
            style={styles.backBtn}
            onPress={() => navigation.goBack()}
          >
            <Text style={styles.backBtnText}>← Scanners</Text>
          </TouchableOpacity>
          <Text style={styles.title}>Message Scanner</Text>
          <Text style={styles.subtitle}>
            Detect social engineering, phishing, smishing, and fraud
          </Text>
        </View>

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
            {/* Source Type Selector */}
            <Text style={styles.inputLabel}>MESSAGE CHANNEL / SOURCE</Text>
            <View style={styles.sourceSelector}>
              {SOURCE_TYPES.map((src) => {
                const isSelected = sourceType === src.id;
                return (
                  <TouchableOpacity
                    key={src.id}
                    style={[
                      styles.sourceTab,
                      isSelected && styles.sourceTabActive
                    ]}
                    onPress={() => setSourceType(src.id)}
                    disabled={loading}
                  >
                    <Text style={styles.sourceIcon}>{src.icon}</Text>
                    <Text
                      style={[
                        styles.sourceLabel,
                        isSelected && styles.sourceLabelActive
                      ]}
                    >
                      {src.label}
                    </Text>
                  </TouchableOpacity>
                );
              })}
            </View>

            {/* Message Text Input */}
            <View style={styles.textAreaHeader}>
              <Text style={styles.inputLabel}>PASTE OR TYPE MESSAGE CONTENT</Text>
              {text.length > 0 && !loading && (
                <TouchableOpacity onPress={handleClear}>
                  <Text style={styles.clearText}>Clear</Text>
                </TouchableOpacity>
              )}
            </View>

            <TextInput
              style={styles.textArea}
              placeholder="e.g. URGENT: Your banking profile has been suspended. Please confirm your details immediately at http://..."
              placeholderTextColor={COLORS.textMuted}
              multiline
              numberOfLines={6}
              textAlignVertical="top"
              value={text}
              editable={!loading}
              onChangeText={(val) => {
                setText(val);
                if (error) setError('');
              }}
            />

            <View style={styles.charCountRow}>
              <Text style={styles.charCountText}>
                {text.length} characters entered
              </Text>
            </View>

            {/* Action Buttons */}
            <View style={styles.buttonRow}>
              <CyberButton
                title={loading ? 'Analyzing Message Text...' : 'Analyze Message'}
                onPress={handleScan}
                loading={loading}
                disabled={loading || !text.trim()}
                style={styles.scanBtn}
              />
              {text.length > 0 && !loading && (
                <TouchableOpacity
                  style={styles.resetBtn}
                  onPress={handleClear}
                >
                  <Text style={styles.resetBtnText}>Clear</Text>
                </TouchableOpacity>
              )}
            </View>
          </View>

          {/* Tips Card */}
          <View style={styles.infoCard}>
            <Text style={styles.infoTitle}>PHISHING INDICATORS MONITORED</Text>
            <View style={styles.bulletRow}>
              <Text style={styles.bullet}>•</Text>
              <Text style={styles.bulletText}>
                Psychological urgency and artificial deadlines ("act within 1 hour")
              </Text>
            </View>
            <View style={styles.bulletRow}>
              <Text style={styles.bullet}>•</Text>
              <Text style={styles.bulletText}>
                Financial and authority impersonation (banks, IRS, delivery couriers)
              </Text>
            </View>
            <View style={styles.bulletRow}>
              <Text style={styles.bullet}>•</Text>
              <Text style={styles.bulletText}>
                Suspicious credential harvesting hyperlinks and obfuscated shortlinks
              </Text>
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
  sourceSelector: {
    flexDirection: 'row',
    gap: 8,
    marginBottom: 18
  },
  sourceTab: {
    flex: 1,
    backgroundColor: COLORS.background,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 10,
    paddingVertical: 10,
    paddingHorizontal: 6,
    alignItems: 'center',
    justifyContent: 'center'
  },
  sourceTabActive: {
    backgroundColor: COLORS.primaryMuted,
    borderColor: COLORS.primary
  },
  sourceIcon: {
    fontSize: 18,
    marginBottom: 4
  },
  sourceLabel: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '700'
  },
  sourceLabelActive: {
    color: COLORS.primary
  },
  textAreaHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8
  },
  clearText: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '700'
  },
  textArea: {
    backgroundColor: COLORS.background,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 12,
    color: COLORS.textPrimary,
    fontSize: 14,
    minHeight: 130
  },
  charCountRow: {
    alignItems: 'flex-end',
    marginTop: 6,
    marginBottom: 16
  },
  charCountText: {
    color: COLORS.textMuted,
    fontSize: 11
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
