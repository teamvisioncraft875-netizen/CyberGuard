import React from 'react';
import { View, ActivityIndicator, Text, StyleSheet } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { useAuth } from '../hooks/useAuth';
import { useTheme } from '../context/ThemeContext';
import { AuthNavigator } from './AuthNavigator';
import { AppNavigator } from './AppNavigator';
import { CyberLogo } from '../components/CyberLogo';

export function RootNavigator() {
  const { isAuthenticated, isLoading } = useAuth();
  const { isDark, colors } = useTheme();

  const navigationTheme = {
    dark: isDark,
    colors: {
      primary: colors.accent,
      background: colors.background,
      card: colors.card,
      text: colors.textPrimary,
      border: colors.border,
      notification: colors.danger
    }
  };

  if (isLoading) {
    return (
      <View style={[styles.splash, { backgroundColor: colors.background }]}>
        <CyberLogo size={56} showText={false} />
        <Text style={[styles.title, { color: colors.textPrimary }]}>
          CYBERGUARD
        </Text>
        <Text style={[styles.subtitle, { color: colors.textMuted }]}>
          Initializing Defense Engine...
        </Text>
        <ActivityIndicator color={colors.accent} size="large" style={styles.loader} />
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
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24
  },
  title: {
    fontSize: 22,
    fontWeight: '800',
    letterSpacing: 2,
    marginTop: 16,
    marginBottom: 4
  },
  subtitle: {
    fontSize: 12,
    letterSpacing: 0.5,
    marginBottom: 20
  },
  loader: {
    marginTop: 8
  }
});
