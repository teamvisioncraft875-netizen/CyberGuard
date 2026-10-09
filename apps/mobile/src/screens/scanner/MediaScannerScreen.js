import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  SafeAreaView,
  ActivityIndicator
} from 'react-native';
import * as DocumentPicker from 'expo-document-picker';
import { COLORS } from '../../constants/colors';
import { useTheme } from '../../context/ThemeContext';
import { AppHeader } from '../../components/AppHeader';
import {
  mediaService,
  MAX_MEDIA_SIZE_BYTES,
  SUPPORTED_EXTENSIONS
} from '../../services/mediaService';
import { CyberButton } from '../../components/CyberButton';

const MEDIA_TYPES = [
  { id: 'image', label: 'Photo / Image', iconName: 'image', subtitle: 'Face & visual manipulation' },
  { id: 'audio', label: 'Voice / Audio', iconName: 'audio', subtitle: 'Voice cloning & speech synthesis' }
];

export function MediaScannerScreen({ navigation }) {
  const [mediaType, setMediaType] = useState('image'); // 'image' | 'audio'
  const [selectedFile, setSelectedFile] = useState(null);
  const [stage, setStage] = useState('idle'); // 'idle' | 'requesting_url' | 'uploading' | 'analyzing'
  const [uploadPercent, setUploadPercent] = useState(null);
  const [error, setError] = useState('');

  const formatFileSize = (bytes) => {
    if (!bytes || bytes <= 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const handlePickFile = async () => {
    if (stage !== 'idle') return;
    setError('');

    try {
      const mimeTypes = mediaType === 'image'
        ? ['image/*']
        : ['audio/*'];

      const result = await DocumentPicker.getDocumentAsync({
        type: mimeTypes,
        copyToCacheDirectory: false,
        multiple: false
      });

      // User cancelled picker
      if (result.canceled || !result.assets || result.assets.length === 0) {
        return;
      }

      const asset = result.assets[0];

      // Validate file size (<= 50 MB)
      if (asset.size && asset.size > MAX_MEDIA_SIZE_BYTES) {
        setError(`Selected file (${formatFileSize(asset.size)}) exceeds maximum allowed limit of 50 MB.`);
        setSelectedFile(null);
        return;
      }

      // Validate extension
      const fileName = asset.name || '';
      const ext = fileName.split('.').pop().toLowerCase();
      const validExtensions = SUPPORTED_EXTENSIONS[mediaType] || [];
      if (ext && !validExtensions.includes(ext)) {
        setError(
          `Unsupported file extension '.${ext}'. Supported ${mediaType} formats: ${validExtensions.join(', ')}`
        );
        setSelectedFile(null);
        return;
      }

      setSelectedFile(asset);
    } catch (pickerErr) {
      console.warn('[MediaScannerScreen.handlePickFile]', pickerErr.message);
      setError('Unable to access file picker. Please try again.');
    }
  };

  const handleClear = () => {
    if (stage !== 'idle') return;
    setSelectedFile(null);
    setError('');
    setUploadPercent(null);
  };

  const handleScan = async () => {
    if (stage !== 'idle') return;
    if (!selectedFile) {
      setError('Please select an image or audio file to scan.');
      return;
    }

    setError('');

    try {
      // Stage 1: Request pre-signed upload URL
      setStage('requesting_url');
      const uploadMetadata = await mediaService.requestUploadUrl({
        mediaType,
        fileSizeBytes: selectedFile.size || 1024 * 100,
        fileName: selectedFile.name
      });

      const { upload_url, file_path } = uploadMetadata;
      if (!upload_url || !file_path) {
        throw new Error('Storage service returned invalid upload authorization');
      }

      // Stage 2: Direct binary upload to signed storage URL
      setStage('uploading');
      setUploadPercent(0);

      await mediaService.uploadToSignedUrl(upload_url, selectedFile, (percent) => {
        setUploadPercent(percent);
      });

      // Stage 3: Request backend deepfake neural analysis
      setStage('analyzing');
      const analysisResult = await mediaService.scanMedia({
        filePath: file_path,
        mediaType
      });

      // Reset local stage
      setStage('idle');
      setUploadPercent(null);

      // Navigate to ScanResultScreen
      navigation.navigate('ScanResult', {
        result: analysisResult,
        scanType: `Media (${mediaType.toUpperCase()})`,
        targetSummary: selectedFile.name
      });
    } catch (err) {
      console.log('[MediaScannerScreen.handleScan Error]', err.message);
      setStage('idle');
      setUploadPercent(null);
      setError(err.message || 'Media analysis failed. Please verify your connection and retry.');
    }
  };

  const { colors } = useTheme();
  const isProcessing = stage !== 'idle';

  return (
    <View style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <AppHeader title="Media Deepfake Scanner" showBack={true} navigation={navigation} />

      <ScrollView contentContainerStyle={styles.content}>
        {error ? (
          <View style={styles.errorBox}>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        ) : null}

        {/* Media Type Selector */}
        <View style={styles.card}>
          <Text style={styles.inputLabel}>SELECT MEDIA CLASSIFICATION</Text>
          <View style={styles.typeSelector}>
            {MEDIA_TYPES.map((t) => {
              const isSelected = mediaType === t.id;
              return (
                <TouchableOpacity
                  key={t.id}
                  style={[styles.typeTab, isSelected && styles.typeTabActive]}
                  onPress={() => {
                    if (!isProcessing) {
                      setMediaType(t.id);
                      setSelectedFile(null);
                      setError('');
                    }
                  }}
                  disabled={isProcessing}
                >
                  <Text style={styles.typeIcon}>{t.icon}</Text>
                  <Text style={[styles.typeLabel, isSelected && styles.typeLabelActive]}>
                    {t.label}
                  </Text>
                  <Text style={styles.typeSubtitle}>{t.subtitle}</Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </View>

        {/* File Picker & Preview Card */}
        <View style={styles.card}>
          <Text style={styles.inputLabel}>ATTACH MEDIA FILE</Text>

          {selectedFile ? (
            <View style={styles.fileSelectedBox}>
              <View style={styles.fileIconBox}>
                <Text style={styles.fileIcon}>{mediaType === 'image' ? '🖼️' : '🎵'}</Text>
              </View>
              <View style={styles.fileDetails}>
                <Text style={styles.fileName} numberOfLines={1}>
                  {selectedFile.name}
                </Text>
                <Text style={styles.fileMeta}>
                  {formatFileSize(selectedFile.size)} • {selectedFile.mimeType || mediaType}
                </Text>
              </View>
              {!isProcessing && (
                <TouchableOpacity onPress={handleClear} style={styles.removeBtn}>
                  <Text style={styles.removeBtnText}>✕</Text>
                </TouchableOpacity>
              )}
            </View>
          ) : (
            <TouchableOpacity
              style={styles.pickerBox}
              activeOpacity={0.8}
              onPress={handlePickFile}
              disabled={isProcessing}
            >
              <Text style={styles.pickerIcon}>📁</Text>
              <Text style={styles.pickerText}>
                Select {mediaType === 'image' ? 'Photo' : 'Audio File'} from Device
              </Text>
              <Text style={styles.pickerHint}>
                Max 50 MB • Formats: {SUPPORTED_EXTENSIONS[mediaType].join(', ')}
              </Text>
            </TouchableOpacity>
          )}

          {/* Honest Stage Indicator */}
          {isProcessing && (
            <View style={styles.stageBox}>
              <ActivityIndicator color={COLORS.primary} size="small" style={styles.stageSpinner} />
              <View style={styles.stageTextContainer}>
                {stage === 'requesting_url' && (
                  <Text style={styles.stageTitle}>Preparing secure storage upload...</Text>
                )}
                {stage === 'uploading' && (
                  <Text style={styles.stageTitle}>
                    Uploading media binary... {uploadPercent !== null ? `(${uploadPercent}%)` : ''}
                  </Text>
                )}
                {stage === 'analyzing' && (
                  <Text style={styles.stageTitle}>Running deepfake neural analysis...</Text>
                )}
                <Text style={styles.stageDesc}>
                  Evaluating facial landmarks, frequency spectra, and synthetic artifacts
                </Text>
              </View>
            </View>
          )}

          {/* Submit Button */}
          <View style={styles.buttonRow}>
            <CyberButton
              title={isProcessing ? 'Analyzing Media...' : `Analyze ${mediaType === 'image' ? 'Image' : 'Audio'}`}
              onPress={handleScan}
              loading={isProcessing}
              disabled={isProcessing || !selectedFile}
              style={styles.scanBtn}
            />
            {selectedFile && !isProcessing && (
              <TouchableOpacity
                style={styles.resetBtn}
                onPress={handleClear}
              >
                <Text style={styles.resetBtnText}>Clear</Text>
              </TouchableOpacity>
            )}
          </View>
        </View>

        {/* Forensic Information */}
        <View style={styles.infoCard}>
          <Text style={styles.infoTitle}>DEEPFAKE ARTIFACTS ANALYZED</Text>
          {mediaType === 'image' ? (
            <>
              <View style={styles.bulletRow}>
                <Text style={styles.bullet}>•</Text>
                <Text style={styles.bulletText}>
                  Facial landmark warping, boundary blending, and gaze incongruities
                </Text>
              </View>
              <View style={styles.bulletRow}>
                <Text style={styles.bullet}>•</Text>
                <Text style={styles.bulletText}>
                  Frequency domain discrepancies and GAN checkerboard artifacts
                </Text>
              </View>
            </>
          ) : (
            <>
              <View style={styles.bulletRow}>
                <Text style={styles.bullet}>•</Text>
                <Text style={styles.bulletText}>
                  Spectrogram phase coherence and unnatural harmonic distribution
                </Text>
              </View>
              <View style={styles.bulletRow}>
                <Text style={styles.bullet}>•</Text>
                <Text style={styles.bulletText}>
                  Voice cloning breath patterns and synthetic acoustic silence
                </Text>
              </View>
            </>
          )}
        </View>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.background
  },
  header: {
    paddingHorizontal: 16,
    paddingTop: 8,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border
  },
  backBtn: {
    marginBottom: 6
  },
  backBtnText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  },
  title: {
    color: COLORS.textPrimary,
    fontSize: 22,
    fontWeight: '800'
  },
  subtitle: {
    color: COLORS.textMuted,
    fontSize: 13,
    marginTop: 2
  },
  content: {
    padding: 16,
    paddingBottom: 32
  },
  errorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.12)',
    borderLeftWidth: 4,
    borderLeftColor: COLORS.danger,
    padding: 12,
    borderRadius: 8,
    marginBottom: 16
  },
  errorText: {
    color: COLORS.danger,
    fontSize: 13,
    lineHeight: 18,
    fontWeight: '600'
  },
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 16,
    padding: 18,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 16
  },
  inputLabel: {
    color: COLORS.textSecondary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 0.8,
    marginBottom: 10
  },
  typeSelector: {
    flexDirection: 'row',
    gap: 10
  },
  typeTab: {
    flex: 1,
    backgroundColor: COLORS.background,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 12,
    padding: 14,
    alignItems: 'center'
  },
  typeTabActive: {
    backgroundColor: COLORS.primaryMuted,
    borderColor: COLORS.primary
  },
  typeIcon: {
    fontSize: 24,
    marginBottom: 6
  },
  typeLabel: {
    color: COLORS.textMuted,
    fontSize: 13,
    fontWeight: '800',
    marginBottom: 2
  },
  typeLabelActive: {
    color: COLORS.primary
  },
  typeSubtitle: {
    color: COLORS.textMuted,
    fontSize: 10,
    textAlign: 'center'
  },
  pickerBox: {
    backgroundColor: COLORS.background,
    borderWidth: 1.5,
    borderStyle: 'dashed',
    borderColor: COLORS.border,
    borderRadius: 12,
    padding: 24,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 16
  },
  pickerIcon: {
    fontSize: 32,
    marginBottom: 8
  },
  pickerText: {
    color: COLORS.primary,
    fontSize: 14,
    fontWeight: '700',
    marginBottom: 4
  },
  pickerHint: {
    color: COLORS.textMuted,
    fontSize: 11
  },
  fileSelectedBox: {
    backgroundColor: COLORS.background,
    borderRadius: 12,
    padding: 14,
    flexDirection: 'row',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)',
    marginBottom: 16
  },
  fileIconBox: {
    width: 40,
    height: 40,
    borderRadius: 8,
    backgroundColor: COLORS.surface,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12
  },
  fileIcon: {
    fontSize: 20
  },
  fileDetails: {
    flex: 1
  },
  fileName: {
    color: COLORS.textPrimary,
    fontSize: 14,
    fontWeight: '700',
    marginBottom: 2
  },
  fileMeta: {
    color: COLORS.textMuted,
    fontSize: 11
  },
  removeBtn: {
    padding: 8
  },
  removeBtnText: {
    color: COLORS.textMuted,
    fontSize: 16,
    fontWeight: '700'
  },
  stageBox: {
    backgroundColor: COLORS.surface,
    borderRadius: 10,
    padding: 12,
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  stageSpinner: {
    marginRight: 12
  },
  stageTextContainer: {
    flex: 1
  },
  stageTitle: {
    color: COLORS.primary,
    fontSize: 12,
    fontWeight: '700',
    marginBottom: 2
  },
  stageDesc: {
    color: COLORS.textMuted,
    fontSize: 10
  },
  buttonRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10
  },
  scanBtn: {
    flex: 1
  },
  resetBtn: {
    paddingHorizontal: 16,
    height: 48,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: COLORS.surface,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  resetBtnText: {
    color: COLORS.textSecondary,
    fontSize: 13,
    fontWeight: '700'
  },
  infoCard: {
    backgroundColor: COLORS.cardSecondary,
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  infoTitle: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.8,
    marginBottom: 10
  },
  bulletRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: 8
  },
  bullet: {
    color: COLORS.primary,
    fontSize: 14,
    marginRight: 8,
    lineHeight: 18
  },
  bulletText: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 18,
    flex: 1
  }
});
