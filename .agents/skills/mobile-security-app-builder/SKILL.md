---
name: mobile-security-app-builder
description: Builds the React Native / Expo mobile application, push notifications, read-aloud TTS alerts, share-sheet universal message checking, and Guardian Mode UI for CYBERGUARD. Activate when developing apps/mobile, configuring Expo notifications, implementing expo-speech, or building the Guardian link workflow.
---

# Mobile Security App Builder — Personal & Guardian Protection

This skill guides the construction of the **React Native / Expo Mobile App** (`apps/mobile/`), specifically tailored for individual users, at-risk family members, and their designated guardians.

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Core Mobile Capabilities
1. **Universal Message Checking (Native Share-Sheet Integration):**
   - Users share suspicious text, links, or media directly from WhatsApp, Telegram, Messages, or Instagram directly into CyberGuard for immediate analysis.
2. **Dual-Tier Push Notifications (FCM):**
   - *Individual Recipient:* Plain-language, low-jargon warning: *"Possible scam detected. Do not click any links."*
   - *Guardian Recipient:* Technical, actionable context: *"Critical Phishing Alert for Alice: Credential harvesting link targeting Chase Bank."*
3. **Automated Read-Aloud Alerts (`expo-speech`):**
   - For `High` and `Critical` alerts, text-to-speech automatically reads the warning out loud to assist elderly or visually-impaired users.
4. **Scoped Voice Command ("Ask CyberGuard"):**
   - Narrow voice prompt handler (e.g. "Check this message") to initiate scanning without complex navigation.
5. **Guardian Mode UI:**
   - Account linking allowing guardians to review wards' past alerts, acknowledge incidents, and remotely suggest password changes or link blocks.

---

## 2. Directory Structure (`apps/mobile/src/`)

```
apps/mobile/src/
├── screens/
│   ├── HomeScreen.tsx            # Safety status, quick-scan action, recent activity
│   ├── ScanResultScreen.tsx      # Risk tier gauge, plain-English explanation, action buttons
│   ├── GuardianScreen.tsx        # Linked family accounts, remote incident stream
│   └── SettingsScreen.tsx        # Notification preferences, TTS toggle, voice triggers
├── components/
│   ├── RiskGauge.tsx             # Visual 0-100 radial meter with calibrated colors
│   ├── ActionCard.tsx            # Recommended action button (Block, Report, Dismiss)
│   └── GuardianBanner.tsx        # Active Guardian Mode status badge
├── services/
│   ├── api.ts                    # Axios client communicating with Node.js Gateway
│   ├── notifications.ts          # Expo Notifications & FCM token registration
│   ├── speech.ts                 # expo-speech wrapper for emergency read-aloud
│   └── shareIntent.ts            # Native share-sheet payload receiver
└── types/                        # Shared TypeScript types matching docs/API_CONTRACT.md
```

---

## 3. Implementation Patterns

### Automated Read-Aloud Trigger (`services/speech.ts`)
```typescript
import * as Speech from 'expo-speech';

export const announceAlert = (riskLevel: string, explanation: string) => {
  if (riskLevel === 'High' || riskLevel === 'Critical') {
    const textToRead = `Security Warning: ${explanation}. Please do not interact with this content.`;
    Speech.stop();
    Speech.speak(textToRead, {
      language: 'en-US',
      pitch: 1.0,
      rate: 0.9, // Slightly slower for clarity
    });
  }
};
```

### Universal Message Checking (Share Intent Handling)
```typescript
import { useEffect } from 'react';
import { useNavigation } from '@react-navigation/native';
import { api } from '@/services/api';

export function useShareIntentHandler() {
  const navigation = useNavigation();

  useEffect(() => {
    // Listen for incoming share intent from OS (WhatsApp, SMS, etc.)
    const handleSharedData = async (sharedContent: { text?: string; url?: string; imageUri?: string }) => {
      if (!sharedContent.text && !sharedContent.url) return;

      const payload = sharedContent.url || sharedContent.text;
      const type = sharedContent.url ? 'url' : 'text';

      navigation.navigate('ScanResult', { status: 'analysing' });

      try {
        const response = await api.post('/api/v1/detect/scan', { payload, type });
        navigation.navigate('ScanResult', { result: response.data });
      } catch (err) {
        navigation.navigate('ScanResult', { error: 'Scan failed' });
      }
    };

    // Attach native listener
    // ...
  }, [navigation]);
}
```

---

## 4. Mobile Engineering Standards Checklist
- [ ] No messy ad-hoc inline styles. Use clean `StyleSheet.create` or shared token constants.
- [ ] FCM push notifications register token with Node.js gateway on login.
- [ ] `expo-speech` activates only on High/Critical alerts and respects user mute settings.
- [ ] Share Intent opens app smoothly and displays scan results without requiring redundant login.
- [ ] Guardian Mode allows toggling between personal view and ward monitoring view.
