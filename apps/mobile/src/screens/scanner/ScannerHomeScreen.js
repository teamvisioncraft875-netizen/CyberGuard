import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  SafeAreaView
} from 'react-native';
import { COLORS } from '../../constants/colors';

export function ScannerHomeScreen({ navigation }) {
  return (
    <SafeAreaView style={styles.safeArea}>
      <View style={styles.header}>
        <TouchableOpacity
          style={styles.backBtn}
          onPress={() => navigation.goBack()}
        >
          <Text style={styles.backBtnText}>← Dashboard</Text>
        </TouchableOpacity>
        <Text style={styles.title}>Threat Scanners</Text>
        <Text style={styles.subtitle}>
          Select a scanner to run immediate heuristic and AI analysis
        </Text>
      </View>

      <ScrollView contentContainerStyle={styles.content}>
        {/* URL Scanner Card */}
        <TouchableOpacity
          style={styles.scannerCard}
          activeOpacity={0.8}
          onPress={() => navigation.navigate('UrlScanner')}
        >
          <View style={styles.iconCircle}>
            <Text style={styles.iconSymbol}>🔗</Text>
          </View>
          <View style={styles.cardInfo}>
            <View style={styles.badgeRow}>
              <Text style={styles.cardTitle}>URL & Website Scanner</Text>
              <View style={styles.activeTag}>
                <Text style={styles.activeTagText}>ACTIVE</Text>
              </View>
            </View>
            <Text style={styles.cardDescription}>
              Check any link or domain for malicious redirects, typosquatting, credential harvesting keywords, and high-risk TLDs.
            </Text>
            <View style={styles.ctaRow}>
              <Text style={styles.ctaText}>Launch URL Scanner →</Text>
            </View>
          </View>
        </TouchableOpacity>

        {/* Message Scanner Card */}
        <TouchableOpacity
          style={styles.scannerCard}
          activeOpacity={0.8}
          onPress={() => navigation.navigate('MessageScanner')}
        >
          <View style={styles.iconCircle}>
            <Text style={styles.iconSymbol}>💬</Text>
          </View>
          <View style={styles.cardInfo}>
            <View style={styles.badgeRow}>
              <Text style={styles.cardTitle}>Message & Phishing Scanner</Text>
              <View style={styles.activeTag}>
                <Text style={styles.activeTagText}>ACTIVE</Text>
              </View>
            </View>
            <Text style={styles.cardDescription}>
              Paste suspicious SMS, email, or social media messages to detect social engineering, urgency manipulation, and scam tactics.
            </Text>
            <View style={styles.ctaRow}>
              <Text style={styles.ctaText}>Launch Message Scanner →</Text>
            </View>
          </View>
        </TouchableOpacity>

        {/* Media / Deepfake Scanner Card */}
        <TouchableOpacity
          style={styles.scannerCard}
          activeOpacity={0.8}
          onPress={() => navigation.navigate('MediaScanner')}
        >
          <View style={styles.iconCircle}>
            <Text style={styles.iconSymbol}>🎙️</Text>
          </View>
          <View style={styles.cardInfo}>
            <View style={styles.badgeRow}>
              <Text style={styles.cardTitle}>Media / Deepfake Scanner</Text>
              <View style={styles.activeTag}>
                <Text style={styles.activeTagText}>ACTIVE</Text>
              </View>
            </View>
            <Text style={styles.cardDescription}>
              Select photos (JPEG, PNG, WebP) or audio recordings (WAV, MP3, OGG, M4A) to detect AI manipulation, synthetic speech, and deepfakes.
            </Text>
            <View style={styles.ctaRow}>
              <Text style={styles.ctaText}>Launch Media Scanner →</Text>
            </View>
          </View>
        </TouchableOpacity>

        {/* Secret / Credential Scanner Card */}
        <TouchableOpacity
          style={styles.scannerCard}
          activeOpacity={0.8}
          onPress={() => navigation.navigate('SecretScanner')}
        >
          <View style={styles.iconCircle}>
            <Text style={styles.iconSymbol}>🔑</Text>
          </View>
          <View style={styles.cardInfo}>
            <View style={styles.badgeRow}>
              <Text style={styles.cardTitle}>Secret & Credential Scanner</Text>
              <View style={styles.activeTag}>
                <Text style={styles.activeTagText}>ACTIVE</Text>
              </View>
            </View>
            <Text style={styles.cardDescription}>
              Inspect code snippets, config files, or text to detect leaked API keys, AWS credentials, database passwords, private keys, and high-entropy tokens.
            </Text>
            <View style={styles.ctaRow}>
              <Text style={styles.ctaText}>Launch Secret Scanner →</Text>
            </View>
          </View>
        </TouchableOpacity>

        {/* Privacy Note */}
        <View style={styles.privacyCard}>
          <Text style={styles.privacyTitle}>🔒 PRIVACY NOTICE</Text>
          <Text style={styles.privacyText}>
            The mobile application does not permanently store, persist, or log submitted scan contents locally. Submissions are processed on-demand for threat analysis.
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.background
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
  scannerCard: {
    backgroundColor: COLORS.card,
    borderRadius: 16,
    padding: 18,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: COLORS.border,
    flexDirection: 'row',
    alignItems: 'flex-start'
  },
  iconCircle: {
    width: 44,
    height: 44,
    borderRadius: 12,
    backgroundColor: COLORS.primaryMuted,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 14,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)'
  },
  iconSymbol: {
    fontSize: 22
  },
  cardInfo: {
    flex: 1
  },
  badgeRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 6
  },
  cardTitle: {
    color: COLORS.textPrimary,
    fontSize: 16,
    fontWeight: '700',
    flex: 1
  },
  activeTag: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    paddingHorizontal: 7,
    paddingVertical: 2,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.3)',
    marginLeft: 6
  },
  activeTagText: {
    color: COLORS.safe,
    fontSize: 9,
    fontWeight: '800'
  },
  cardDescription: {
    color: COLORS.textSecondary,
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 12
  },
  ctaRow: {
    flexDirection: 'row',
    alignItems: 'center'
  },
  ctaText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  },
  privacyCard: {
    backgroundColor: COLORS.cardSecondary,
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginTop: 8
  },
  privacyTitle: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.8,
    marginBottom: 4
  },
  privacyText: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 17
  }
});
