import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { COLORS } from '../constants/colors';
import { getRiskColor } from '../utils/riskHelpers';

/**
 * Renders verified exposed secret items from the backend response.
 * Safely displays only the classification, severity, and line location without
 * ever rendering raw credential values.
 */
export function DetectedSecretList({ detectedSecrets = [] }) {
  if (!Array.isArray(detectedSecrets) || detectedSecrets.length === 0) {
    return null;
  }

  const formatSecretType = (type) => {
    if (!type) return 'Unknown Credential';
    return type
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <View style={styles.card}>
      <View style={styles.header}>
        <Text style={styles.heading}>EXPOSED SECRETS IDENTIFIED</Text>
        <View style={styles.countBadge}>
          <Text style={styles.countText}>{detectedSecrets.length}</Text>
        </View>
      </View>

      {detectedSecrets.map((secret, index) => {
        const severityColor = getRiskColor(secret.severity);
        return (
          <View key={index} style={styles.itemRow}>
            <View style={styles.itemLeft}>
              <View style={styles.itemTitleRow}>
                <Text style={styles.itemTitle}>{formatSecretType(secret.secret_type)}</Text>
                <View
                  style={[
                    styles.severityBadge,
                    { borderColor: severityColor, backgroundColor: `${severityColor}22` }
                  ]}
                >
                  <Text style={[styles.severityText, { color: severityColor }]}>
                    {(secret.severity || 'high').toUpperCase()}
                  </Text>
                </View>
              </View>
              {secret.location ? (
                <Text style={styles.locationText}>📍 {secret.location}</Text>
              ) : null}
            </View>
          </View>
        );
      })}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 18,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.4)',
    borderLeftWidth: 4,
    borderLeftColor: COLORS.critical
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 14
  },
  heading: {
    color: COLORS.critical,
    fontSize: 12,
    fontWeight: '800',
    letterSpacing: 1
  },
  countBadge: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.3)'
  },
  countText: {
    color: COLORS.critical,
    fontSize: 11,
    fontWeight: '800'
  },
  itemRow: {
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 255, 255, 0.06)'
  },
  itemLeft: {
    flex: 1
  },
  itemTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 4
  },
  itemTitle: {
    color: COLORS.textPrimary,
    fontSize: 14,
    fontWeight: '700'
  },
  severityBadge: {
    paddingHorizontal: 7,
    paddingVertical: 2,
    borderRadius: 4,
    borderWidth: 1
  },
  severityText: {
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  locationText: {
    color: COLORS.textMuted,
    fontSize: 12,
    fontFamily: 'monospace'
  }
});
