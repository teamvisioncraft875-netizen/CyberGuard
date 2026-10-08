// Test environment setup for apps/mobile
const Module = require('module');

// In-memory mock storage for SecureStore
const secureStoreMock = new Map();

// Native module mocks
const originalRequire = Module.prototype.require;
Module.prototype.require = function (modulePath) {
  if (modulePath === 'expo-secure-store') {
    return {
      getItemAsync: async (key) => secureStoreMock.get(key) || null,
      setItemAsync: async (key, value) => {
        secureStoreMock.set(key, String(value));
      },
      deleteItemAsync: async (key) => {
        secureStoreMock.delete(key);
      }
    };
  }

  if (modulePath === 'react-native') {
    return {
      Platform: { OS: 'ios' },
      StyleSheet: { create: (styles) => styles },
      View: 'View',
      Text: 'Text',
      TouchableOpacity: 'TouchableOpacity',
      TextInput: 'TextInput',
      ScrollView: 'ScrollView',
      ActivityIndicator: 'ActivityIndicator',
      SafeAreaView: 'SafeAreaView',
      RefreshControl: 'RefreshControl',
      FlatList: 'FlatList'
    };
  }

  if (modulePath === 'expo-document-picker') {
    return {
      getDocumentAsync: async () => ({ canceled: true, assets: [] })
    };
  }

  if (modulePath === 'socket.io-client') {
    return {
      io: (url, opts) => {
        const eventHandlers = {};
        return {
          connected: true,
          on: (event, cb) => {
            eventHandlers[event] = cb;
          },
          disconnect: () => {},
          _trigger: (event, data) => {
            if (eventHandlers[event]) eventHandlers[event](data);
          }
        };
      }
    };
  }

  return originalRequire.apply(this, arguments);
};

module.exports = {
  secureStoreMock,
  resetSecureStore: () => secureStoreMock.clear()
};
