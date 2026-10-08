import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

// In-memory fallback for environments without SecureStore support
const memoryStorage = new Map();

export const storageService = {
  async getItem(key) {
    try {
      if (Platform.OS === 'web') {
        return localStorage.getItem(key) || memoryStorage.get(key) || null;
      }
      return await SecureStore.getItemAsync(key);
    } catch (err) {
      console.warn(`[storageService.getItem] Fallback reading ${key}:`, err.message);
      return memoryStorage.get(key) || null;
    }
  },

  async setItem(key, value) {
    try {
      const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
      if (Platform.OS === 'web') {
        localStorage.setItem(key, stringValue);
        memoryStorage.set(key, stringValue);
        return;
      }
      await SecureStore.setItemAsync(key, stringValue);
    } catch (err) {
      console.warn(`[storageService.setItem] Fallback writing ${key}:`, err.message);
      memoryStorage.set(key, typeof value === 'string' ? value : JSON.stringify(value));
    }
  },

  async removeItem(key) {
    try {
      if (Platform.OS === 'web') {
        localStorage.removeItem(key);
        memoryStorage.delete(key);
        return;
      }
      await SecureStore.deleteItemAsync(key);
    } catch (err) {
      console.warn(`[storageService.removeItem] Fallback deleting ${key}:`, err.message);
      memoryStorage.delete(key);
    }
  },

  async clear() {
    try {
      memoryStorage.clear();
      if (Platform.OS === 'web') {
        localStorage.clear();
      }
    } catch (err) {
      console.warn('[storageService.clear]', err.message);
    }
  }
};
