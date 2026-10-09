import React from 'react';
import { View, TouchableOpacity, StyleSheet, Platform, Text } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTheme } from '../context/ThemeContext';
import { Icon } from './Icon';

const TABS = [
  { key: 'Dashboard', icon: 'home', label: 'Home' },
  { key: 'ScannerHome', icon: 'scan', label: 'Scan' },
  { key: 'IncidentList', icon: 'activity', label: 'Incidents' },
  { key: 'Guardian', icon: 'guardian', label: 'Guardian' },
  { key: 'SecurityActivity', icon: 'settings', label: 'SecOps' }
];

export function BottomTabBar({ activeRoute, navigation }) {
  const { colors, isDark } = useTheme();
  const insets = useSafeAreaInsets();

  const bottomInset = Math.max(insets.bottom, Platform.OS === 'android' ? 8 : 4);

  return (
    <View
      style={[
        styles.bar,
        {
          backgroundColor: colors.card,
          borderTopColor: colors.border,
          paddingBottom: bottomInset,
          height: 56 + bottomInset
        }
      ]}
    >
      {TABS.map((tab) => {
        const isActive = activeRoute === tab.key;
        return (
          <TouchableOpacity
            key={tab.key}
            style={styles.tabItem}
            activeOpacity={0.7}
            onPress={() => navigation?.navigate(tab.key)}
            accessibilityRole="tab"
            accessibilityLabel={tab.label}
            accessibilityState={{ selected: isActive }}
          >
            <View style={styles.iconWrapper}>
              <Icon
                name={tab.icon}
                size={20}
                color={isActive ? colors.accent : colors.textMuted}
              />
              <Text
                style={[
                  styles.tabLabel,
                  {
                    color: isActive ? (isDark ? '#FFFFFF' : colors.accent) : colors.textMuted,
                    fontWeight: isActive ? '700' : '500'
                  }
                ]}
                numberOfLines={1}
              >
                {tab.label}
              </Text>
              {isActive && (
                <View
                  style={[
                    styles.activeIndicator,
                    { backgroundColor: colors.accent }
                  ]}
                />
              )}
            </View>
          </TouchableOpacity>
        );
      })}
    </View>
  );
}

const styles = StyleSheet.create({
  bar: {
    flexDirection: 'row',
    borderTopWidth: 1,
    alignItems: 'center',
    justifyContent: 'space-around',
    width: '100%',
    zIndex: 20
  },
  tabItem: {
    flex: 1,
    height: 54,
    justifyContent: 'center',
    alignItems: 'center'
  },
  iconWrapper: {
    alignItems: 'center',
    justifyContent: 'center',
    height: 48,
    position: 'relative',
    gap: 2
  },
  tabLabel: {
    fontSize: 9,
    letterSpacing: 0.3
  },
  activeIndicator: {
    position: 'absolute',
    top: 0,
    width: 16,
    height: 2,
    borderRadius: 1
  }
});
