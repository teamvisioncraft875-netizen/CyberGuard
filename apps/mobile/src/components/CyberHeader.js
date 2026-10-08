import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { COLORS } from '../constants/colors';
import { useAuth } from '../hooks/useAuth';

export function CyberHeader({ title, subtitle, showLogout = true }) {
  const { user, logout } = useAuth();

  return (
    <View style={styles.container}>
      <View style={styles.topRow}>
        <View style={styles.brandRow}>
          <View style={styles.shieldIcon}>
            <Text style={styles.shieldSymbol}>🛡️</Text>
          </View>
          <View>
            <Text style={styles.brandText}>CYBERGUARD</Text>
            <Text style={styles.tagline}>AUTONOMOUS DEFENSE</Text>
          </View>
        </View>

        {showLogout && (
          <View style={styles.userSection}>
            {user && (
              <View style={styles.roleChip}>
                <Text style={styles.roleText}>
                  {(user.role || 'user').toUpperCase()}
                </Text>
              </View>
            )}
            <TouchableOpacity onPress={logout} style={styles.logoutBtn}>
              <Text style={styles.logoutText}>Logout</Text>
            </TouchableOpacity>
          </View>
        )}
      </View>

      {title && (
        <View style={styles.titleSection}>
          <Text style={styles.title}>{title}</Text>
          {subtitle && <Text style={styles.subtitle}>{subtitle}</Text>}
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    paddingHorizontal: 16,
    paddingTop: 12,
    paddingBottom: 16,
    backgroundColor: COLORS.background,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border
  },
  topRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  brandRow: {
    flexDirection: 'row',
    alignItems: 'center'
  },
  shieldIcon: {
    width: 32,
    height: 32,
    borderRadius: 8,
    backgroundColor: COLORS.primaryMuted,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 10,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)'
  },
  shieldSymbol: {
    fontSize: 16
  },
  brandText: {
    color: COLORS.primary,
    fontSize: 16,
    fontWeight: '900',
    letterSpacing: 1.2
  },
  tagline: {
    color: COLORS.textMuted,
    fontSize: 9,
    fontWeight: '700',
    letterSpacing: 1
  },
  userSection: {
    flexDirection: 'row',
    alignItems: 'center'
  },
  roleChip: {
    backgroundColor: 'rgba(0, 240, 255, 0.1)',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 4,
    marginRight: 8,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.2)'
  },
  roleText: {
    color: COLORS.primary,
    fontSize: 10,
    fontWeight: '800'
  },
  logoutBtn: {
    paddingHorizontal: 10,
    paddingVertical: 5,
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: 6,
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.2)'
  },
  logoutText: {
    color: COLORS.danger,
    fontSize: 11,
    fontWeight: '700'
  },
  titleSection: {
    marginTop: 14
  },
  title: {
    color: COLORS.textPrimary,
    fontSize: 20,
    fontWeight: '800'
  },
  subtitle: {
    color: COLORS.textSecondary,
    fontSize: 13,
    marginTop: 2
  }
});
