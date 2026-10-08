import React from 'react';
import { View, ActivityIndicator, Text, StyleSheet } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { useAuth } from '../hooks/useAuth';
import { AuthNavigator } from './AuthNavigator';
import { AppNavigator } from './AppNavigator';
import { COLORS } from '../constants/colors';

const navigationTheme = {
  dark: true,
  colors: {
    primary: COLORS.primary,
    background: COLORS.background,
    card: COLORS.card,
    text: COLORS.textPrimary,
    border: COLORS.border,
    notification: COLORS.danger
  }
};

export function RootNavigator() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <View style={styles.splash}>
        <View style={styles.badge}>
          <Text style={styles.badgeIcon}>🛡️</Text>
        </View>
        <Text style={styles.title}>CYBERGUARD</Text>
        <Text style={styles.subtitle}>Initializing Defense Engine...</Text>
        <ActivityIndicator color={COLORS.primary} size="large" style={styles.loader} />
      </View>
    );
  }

  return (
    <NavigationContainer theme={navigationTheme}>
      {isAuthenticated ? <AppNavigator /> : <AuthNavigator />}
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  splash: {
    flex: 1,
    backgroundColor: COLORS.background,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24
  },
  badge: {
    width: 64,
    height: 64,
    borderRadius: 18,
    backgroundColor: COLORS.card,
    borderWidth: 1.5,
    borderColor: COLORS.primary,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 16
  },
  badgeIcon: {
    fontSize: 32
  },
  title: {
    color: COLORS.primary,
    fontSize: 24,
    fontWeight: '900',
    letterSpacing: 2,
    marginBottom: 4
  },
  subtitle: {
    color: COLORS.textMuted,
    fontSize: 13,
    marginBottom: 20
  },
  loader: {
    marginTop: 8
  }
});
