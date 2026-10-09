import { Platform } from 'react-native';

// Resolve appropriate default localhost depending on platform
const getHostUrl = () => {
  if (process.env.EXPO_PUBLIC_API_URL) {
    return process.env.EXPO_PUBLIC_API_URL;
  }
  // Android emulator routes host machine loopback to 10.0.2.2
  if (Platform.OS === 'android') {
    return 'http://10.0.2.2:5000/api/v1';
  }
  // iOS simulator and Web loopback
  return 'http://localhost:5000/api/v1';
};

const getWsUrl = () => {
  if (process.env.EXPO_PUBLIC_WS_URL) {
    return process.env.EXPO_PUBLIC_WS_URL;
  }
  if (Platform.OS === 'android') {
    return 'http://10.0.2.2:5000';
  }
  return 'http://localhost:5000';
};

export const CONFIG = {
  API_URL: getHostUrl(),
  WS_URL: getWsUrl(),
  TOKEN_KEY: 'cyberguard_access_token',
  REFRESH_TOKEN_KEY: 'cyberguard_refresh_token',
  USER_KEY: 'cyberguard_user_profile',
  CUSTOM_API_URL_KEY: 'cyberguard_custom_api_url'
};
