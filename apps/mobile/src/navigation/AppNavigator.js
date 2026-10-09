import React from 'react';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { useTheme } from '../context/ThemeContext';
import { DashboardScreen } from '../screens/dashboard/DashboardScreen';
import { IncidentListScreen } from '../screens/incidents/IncidentListScreen';
import { IncidentDetailScreen } from '../screens/incidents/IncidentDetailScreen';
import { ScannerHomeScreen } from '../screens/scanner/ScannerHomeScreen';
import { UrlScannerScreen } from '../screens/scanner/UrlScannerScreen';
import { MessageScannerScreen } from '../screens/scanner/MessageScannerScreen';
import { MediaScannerScreen } from '../screens/scanner/MediaScannerScreen';
import { SecretScannerScreen } from '../screens/scanner/SecretScannerScreen';
import { ScanResultScreen } from '../screens/scanner/ScanResultScreen';
import { GuardianScreen } from '../screens/guardian/GuardianScreen';
import { SecurityActivityScreen } from '../screens/security/SecurityActivityScreen';

const Stack = createNativeStackNavigator();

export function AppNavigator() {
  const { colors } = useTheme();

  return (
    <Stack.Navigator
      initialRouteName="Dashboard"
      screenOptions={{
        headerShown: false,
        animation: 'slide_from_right',
        contentStyle: { backgroundColor: colors.background }
      }}
    >
      <Stack.Screen name="Dashboard" component={DashboardScreen} />
      <Stack.Screen name="IncidentList" component={IncidentListScreen} />
      <Stack.Screen name="IncidentDetail" component={IncidentDetailScreen} />
      <Stack.Screen name="ScannerHome" component={ScannerHomeScreen} />
      <Stack.Screen name="UrlScanner" component={UrlScannerScreen} />
      <Stack.Screen name="MessageScanner" component={MessageScannerScreen} />
      <Stack.Screen name="MediaScanner" component={MediaScannerScreen} />
      <Stack.Screen name="SecretScanner" component={SecretScannerScreen} />
      <Stack.Screen name="ScanResult" component={ScanResultScreen} />
      <Stack.Screen name="Guardian" component={GuardianScreen} />
      <Stack.Screen name="SecurityActivity" component={SecurityActivityScreen} />
    </Stack.Navigator>
  );
}
