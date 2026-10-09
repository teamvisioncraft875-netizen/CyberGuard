import React, { useState } from 'react';
import { View, StyleSheet, TouchableOpacity, Text, Alert, Platform, StatusBar } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../hooks/useAuth';
import { CyberLogo } from './CyberLogo';
import { ThemeToggle } from './ThemeToggle';
import { CopilotToggle } from './CopilotToggle';
import { CopilotModal } from './CopilotModal';
import { Icon } from './Icon';

export function AppHeader({ title, showBack = false, onBack, navigation }) {
  const { colors, isDark } = useTheme();
  const { logout, user } = useAuth();
  const [copilotOpen, setCopilotOpen] = useState(false);
  const insets = useSafeAreaInsets();

  // Inset calculation: on Android, insets.top might be 0 if translucent status bar is used,
  // so fallback to StatusBar.currentHeight to prevent header clipping into the status bar.
  const statusBarHeight = Platform.OS === 'android' ? (StatusBar.currentHeight || 28) : 0;
  const topInset = Math.max(insets.top, statusBarHeight);

  const handleProfilePress = () => {
    Alert.alert(
      'Account Session',
      `Signed in as ${user?.email || 'Operator'}\nRole: ${user?.role || 'Individual Defender'}\nTheme: ${isDark ? 'Dark (Enterprise)' : 'Light (Executive)'}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Log Out', style: 'destructive', onPress: () => logout() }
      ]
    );
  };

  return (
    <>
      <View
        style={[
          styles.containerWrapper,
          {
            paddingTop: topInset,
            backgroundColor: colors.background,
            borderBottomColor: colors.border
          }
        ]}
      >
        <View style={styles.headerBar}>
          <View style={styles.leftGroup}>
            {showBack ? (
              <TouchableOpacity
                style={[styles.backBtn, { borderColor: colors.border, backgroundColor: colors.surface }]}
                onPress={onBack || (() => navigation?.goBack())}
                activeOpacity={0.7}
                accessibilityLabel="Go Back"
              >
                <Icon name="arrowLeft" size={16} color={colors.textPrimary} />
              </TouchableOpacity>
            ) : null}

            <CyberLogo
              size={showBack ? 28 : 32}
              showText={!showBack}
              onPress={() => navigation?.navigate('Dashboard')}
            />

            {showBack && title ? (
              <Text
                style={[styles.screenTitle, { color: colors.textPrimary }]}
                numberOfLines={1}
              >
                {title}
              </Text>
            ) : null}
          </View>

          <View style={styles.rightGroup}>
            <ThemeToggle />
            <CopilotToggle onPress={() => setCopilotOpen(true)} />
            <TouchableOpacity
              style={[styles.profileBtn, { borderColor: colors.border, backgroundColor: colors.surface }]}
              onPress={handleProfilePress}
              activeOpacity={0.7}
              accessibilityLabel="User Profile and Logout"
            >
              <Icon name="user" size={16} color={colors.textSecondary} />
            </TouchableOpacity>
          </View>
        </View>
      </View>

      <CopilotModal
        visible={copilotOpen}
        onClose={() => setCopilotOpen(false)}
      />
    </>
  );
}

const styles = StyleSheet.create({
  containerWrapper: {
    borderBottomWidth: 1,
    width: '100%',
    zIndex: 20
  },
  headerBar: {
    height: 56,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16
  },
  leftGroup: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    flex: 1
  },
  backBtn: {
    width: 38,
    height: 38,
    borderRadius: 8,
    borderWidth: 1,
    justifyContent: 'center',
    alignItems: 'center'
  },
  screenTitle: {
    fontSize: 16,
    fontWeight: '700',
    letterSpacing: 0.2,
    flex: 1,
    marginLeft: 2
  },
  rightGroup: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10
  },
  profileBtn: {
    width: 38,
    height: 38,
    borderRadius: 8,
    borderWidth: 1,
    justifyContent: 'center',
    alignItems: 'center'
  }
});
