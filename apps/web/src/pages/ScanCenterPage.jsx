import React, { useState } from 'react';
import { cn } from '../utils/cn';
import { normalizeRisk } from '../utils/risk';
import { normalizeAction } from '../utils/actions';
import { RiskBadge, Badge, Button, Input, Select, Card, CardContent, EmptyState } from '../components/ui';
import { scanService } from '../services';
import { MediaDropzone, validateMediaFile } from '../components/MediaDropzone';
import {
  Radar,
  Mail,
  Globe,
  FileImage,
  FileAudio,
  AlertCircle,
  CheckCircle2,
  RotateCcw,
  Sparkles,
  ArrowRight,
  Shield,
  Layers,
  UploadCloud,
  Link2,
} from 'lucide-react';

export function ScanCenterPage() {
  const [activeTab, setActiveTab] = useState('message'); // 'message' | 'url' | 'media'

  // Form states
  const [messageText, setMessageText] = useState('');
  const [sourceType, setSourceType] = useState('email'); // 'email' | 'sms' | 'social'

  const [targetUrl, setTargetUrl] = useState('');

  // Media tab states
  const [mediaInputMode, setMediaInputMode] = useState('upload'); // 'upload' | 'url'
  const [selectedMediaFile, setSelectedMediaFile] = useState(null);
  const [mediaUrl, setMediaUrl] = useState('');
  const [mediaType, setMediaType] = useState('image'); // 'image' | 'audio'
  const [mediaValidationError, setMediaValidationError] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [analyzedFileName, setAnalyzedFileName] = useState(null);

  // Lifecycle stage: 'IDLE' | 'FILE_SELECTED' | 'VALIDATING' | 'REQUESTING_UPLOAD_URL' | 'UPLOADING' | 'ANALYZING' | 'RESULT' | 'ERROR'
  const [uploadStage, setUploadStage] = useState('IDLE');

  // Inspection lifecycle states
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  const handleReset = () => {
    setScanResult(null);
    setErrorMessage(null);
    setMediaValidationError(null);
    setUploadProgress(0);
    setAnalyzedFileName(null);
    setUploadStage(selectedMediaFile ? 'FILE_SELECTED' : 'IDLE');
  };

  const handleScan = async (e) => {
    e?.preventDefault();
    setErrorMessage(null);
    setMediaValidationError(null);
    setScanResult(null);
    setIsScanning(true);

    try {
      let result;
      if (activeTab === 'message') {
        if (!messageText.trim()) {
          setErrorMessage('Please enter or paste the message text to analyze.');
          setIsScanning(false);
          return;
        }
        result = await scanService.checkMessage({
          text: messageText.trim(),
          source_type: sourceType,
        });
      } else if (activeTab === 'url') {
        if (!targetUrl.trim()) {
          setErrorMessage('Please enter a target URL to inspect.');
          setIsScanning(false);
          return;
        }
        result = await scanService.checkUrl({
          url: targetUrl.trim(),
        });
      } else if (activeTab === 'media') {
        if (mediaInputMode === 'upload') {
          if (!selectedMediaFile) {
            setErrorMessage('Please select or drag & drop an image or audio file to inspect.');
            setUploadStage('INVALID_FILE');
            setIsScanning(false);
            return;
          }

          // 1. Client-side Validation
          setUploadStage('VALIDATING');
          const validation = validateMediaFile(selectedMediaFile);
          if (!validation.valid) {
            setMediaValidationError(validation.error);
            setErrorMessage(validation.error);
            setUploadStage('INVALID_FILE');
            setIsScanning(false);
            return;
          }

          // 2. Request Signed Upload URL from Gateway
          setUploadStage('REQUESTING_UPLOAD_URL');
          setUploadProgress(0);
          let uploadUrlData;
          try {
            uploadUrlData = await scanService.getUploadUrl({
              media_type: mediaType,
              file_size_bytes: selectedMediaFile.size,
              file_name: selectedMediaFile.name,
            });
          } catch (uploadUrlErr) {
            if (uploadUrlErr.status === 401) {
              setUploadStage('SESSION_EXPIRED');
              throw uploadUrlErr;
            }
            setUploadStage('UPLOAD_URL_FAILED');
            throw new Error(
              uploadUrlErr.message || 'Failed to generate secure upload credentials from gateway.'
            );
          }

          if (!uploadUrlData?.upload_url || !uploadUrlData?.file_path) {
            setUploadStage('UPLOAD_URL_FAILED');
            throw new Error('Invalid upload credentials received from gateway.');
          }

          // 3. Upload Raw Binary Directly to Storage Signed URL
          setUploadStage('UPLOADING');
          try {
            await scanService.uploadFileToSignedUrl(
              uploadUrlData.upload_url,
              selectedMediaFile,
              (percent) => {
                setUploadProgress(percent);
              }
            );
          } catch (uploadErr) {
            setUploadStage('UPLOAD_FAILED');
            throw new Error(
              uploadErr.message || 'Direct upload to media storage failed. Please check network connectivity and retry.'
            );
          }

          // 4. Submit Stored File Reference for AI Deepfake Inspection
          setUploadStage('ANALYZING');
          setAnalyzedFileName(selectedMediaFile.name);
          try {
            result = await scanService.checkMedia({
              file_path: uploadUrlData.file_path,
              media_type: mediaType,
            });
            setUploadStage('RESULT');
          } catch (analysisErr) {
            setUploadStage('ANALYSIS_FAILED');
            throw analysisErr;
          }
        } else {
          // Fallback: Manual Media Public URL Mode
          if (!mediaUrl.trim()) {
            setErrorMessage('Please enter a valid media file URL.');
            setIsScanning(false);
            return;
          }
          setAnalyzedFileName(mediaUrl.trim().split('/').pop() || 'Remote Media');
          result = await scanService.checkMedia({
            file_url: mediaUrl.trim(),
            media_type: mediaType,
          });
          setUploadStage('RESULT');
        }
      }

      setScanResult(result);
    } catch (err) {
      if (err.status === 401 || err.code === 'UNAUTHORIZED') {
        setErrorMessage('Authentication session expired. Please sign in again.');
      } else if (err.status === 429 || err.code === 'RATE_LIMITED') {
        setErrorMessage(
          'Too many scan requests. Rate limit is 100 requests per 15 minutes. Please wait before retrying.'
        );
      } else if (err.status === 502 || err.code === 'DETECTION_ENGINE_UNAVAILABLE') {
        setErrorMessage(
          'Detection engine service is currently unavailable. Please verify the AI/ML inspection service is active.'
        );
      } else if (err.code === 'UPLOAD_FAILED' || err.code === 'NETWORK_ERROR') {
        setErrorMessage(err.message || 'Media upload failed due to a network or storage error.');
      } else {
        setErrorMessage(
          err.message || 'Threat scan failed. Please verify the input payload and gateway connection.'
        );
      }
      setUploadStage('ERROR');
    } finally {
      setIsScanning(false);
    }
  };

  // Normalized recommended actions
  const normalizedActions = React.useMemo(() => {
    if (!scanResult?.recommended_actions) {
      if (scanResult?.recommended_action) {
        return [normalizeAction(scanResult.recommended_action, 0)];
      }
      return [];
    }
    return Array.isArray(scanResult.recommended_actions)
      ? scanResult.recommended_actions.map((act, idx) => normalizeAction(act, idx))
      : [];
  }, [scanResult]);

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto w-full pb-12 font-sans">
      {/* 1. Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="font-headline text-2xl lg:text-3xl font-bold tracking-tight text-foreground">
            Scan Center
          </h1>
          <p className="font-body text-xs text-muted-foreground mt-1">
            Dispatch communications, web indicators, and media files to AI detection models
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center bg-muted/60 p-1 rounded-lg border border-border text-xs font-mono">
          <button
            type="button"
            onClick={() => {
              setActiveTab('message');
              handleReset();
            }}
            className={cn(
              'px-3 py-1.5 rounded transition-colors flex items-center gap-1.5',
              activeTab === 'message'
                ? 'bg-card text-foreground font-semibold shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Message</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveTab('url');
              handleReset();
            }}
            className={cn(
              'px-3 py-1.5 rounded transition-colors flex items-center gap-1.5',
              activeTab === 'url'
                ? 'bg-card text-foreground font-semibold shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>URL</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveTab('media');
              handleReset();
            }}
            className={cn(
              'px-3 py-1.5 rounded transition-colors flex items-center gap-1.5',
              activeTab === 'media'
                ? 'bg-card text-foreground font-semibold shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <FileImage className="w-3.5 h-3.5" />
            <span>Media</span>
          </button>
        </div>
      </div>

      {/* 2. Main Scan Layout: Grid with Form on Left, Output on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Input Form (6 cols) */}
        <div className="lg:col-span-6 bg-card rounded-xl border border-border p-6 space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <span className="font-headline font-bold text-sm text-foreground flex items-center gap-2">
              <Radar className="w-4 h-4 text-primary" />
              {activeTab === 'message'
                ? 'Message Threat Analysis'
                : activeTab === 'url'
                ? 'Destination URL Inspection'
                : 'Multimedia Deepfake Scan'}
            </span>
            <span className="text-[10px] font-mono uppercase text-muted-foreground bg-muted/60 px-2 py-0.5 rounded">
              POST /api/v1/check/{activeTab}
            </span>
          </div>

          <form onSubmit={handleScan} className="space-y-4">
            {/* TAB 1: MESSAGE SCAN */}
            {activeTab === 'message' && (
              <>
                <Select
                  label="Message Source Type"
                  value={sourceType}
                  onChange={(e) => setSourceType(e.target.value)}
                  helperText="Required by detection classifier: 'email', 'sms', or 'social'"
                >
                  <option value="email">Email Communication</option>
                  <option value="sms">SMS / Text Message</option>
                  <option value="social">Social Media Message</option>
                </Select>

                <div className="space-y-1.5">
                  <div className="flex justify-between items-center text-xs font-semibold uppercase text-foreground/80 tracking-wide">
                    <label htmlFor="msg-textarea">Message Content</label>
                    <button
                      type="button"
                      onClick={() =>
                        setMessageText(
                          'Your bank account access has been suspended due to unauthorized activity. Please verify your identity immediately at: https://secure-bank-login-verify.com/auth?token=9281'
                        )
                      }
                      className="text-primary font-normal hover:underline text-[11px] normal-case"
                    >
                      Paste Phishing Sample
                    </button>
                  </div>
                  <textarea
                    id="msg-textarea"
                    rows={5}
                    value={messageText}
                    onChange={(e) => setMessageText(e.target.value)}
                    placeholder="Paste email text, SMS message, or prompt to inspect..."
                    className="w-full rounded-lg border border-input bg-background p-3 text-xs text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring font-sans"
                    required
                  />
                </div>
              </>
            )}

            {/* TAB 2: URL SCAN */}
            {activeTab === 'url' && (
              <>
                <Input
                  label="Target URL"
                  type="url"
                  placeholder="https://suspicious-portal-login.net/auth"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  helperText="Target URL will be inspected for typosquatting, malware domains, and SSL integrity"
                  required
                />
                <button
                  type="button"
                  onClick={() => setTargetUrl('https://paypa1-security-verification.com/login')}
                  className="text-primary text-[11px] hover:underline"
                >
                  Load Typosquatted Sample
                </button>
              </>
            )}

            {/* TAB 3: MEDIA SCAN */}
            {activeTab === 'media' && (
              <div className="space-y-4">
                {/* Input Mode Selector: Direct Upload vs Remote URL */}
                <div className="flex items-center gap-1 p-1 bg-muted/60 rounded-lg border border-border text-xs">
                  <button
                    type="button"
                    onClick={() => {
                      setMediaInputMode('upload');
                      setErrorMessage(null);
                    }}
                    className={cn(
                      'flex-1 py-1.5 px-3 rounded-md font-medium transition-all text-center flex items-center justify-center gap-2',
                      mediaInputMode === 'upload'
                        ? 'bg-card text-foreground shadow-sm font-semibold'
                        : 'text-muted-foreground hover:text-foreground'
                    )}
                  >
                    <UploadCloud className="w-3.5 h-3.5" />
                    <span>Upload Media File</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setMediaInputMode('url');
                      setErrorMessage(null);
                    }}
                    className={cn(
                      'flex-1 py-1.5 px-3 rounded-md font-medium transition-all text-center flex items-center justify-center gap-2',
                      mediaInputMode === 'url'
                        ? 'bg-card text-foreground shadow-sm font-semibold'
                        : 'text-muted-foreground hover:text-foreground'
                    )}
                  >
                    <Link2 className="w-3.5 h-3.5" />
                    <span>Remote Media URL</span>
                  </button>
                </div>

                {/* Media Classification Select */}
                <Select
                  label="Media Classification"
                  value={mediaType}
                  onChange={(e) => setMediaType(e.target.value)}
                  helperText={
                    mediaType === 'image'
                      ? 'Evaluates portrait facial artifacts, boundary blending, and generative synthesis (ViT/CNN).'
                      : 'Evaluates acoustic spectral anomalies, vocal tract discontinuities, and voice cloning (ASVspoof).'
                  }
                  disabled={isScanning}
                >
                  <option value="image">Image File (Deepfake / Facial Synthesis)</option>
                  <option value="audio">Audio Clip (Voice Clone / Speech Synthesis)</option>
                </Select>

                {mediaInputMode === 'upload' ? (
                  <MediaDropzone
                    file={selectedMediaFile}
                    onFileSelect={(file, detectedType, error) => {
                      if (error) {
                        setMediaValidationError(error);
                        setUploadStage('INVALID_FILE');
                        return;
                      }
                      setSelectedMediaFile(file);
                      if (detectedType) {
                        setMediaType(detectedType);
                      }
                      setMediaValidationError(null);
                      setErrorMessage(null);
                      setUploadStage('FILE_SELECTED');
                    }}
                    onFileRemove={() => {
                      setSelectedMediaFile(null);
                      setUploadProgress(0);
                      setUploadStage('IDLE');
                      setMediaValidationError(null);
                      setErrorMessage(null);
                    }}
                    uploadStage={uploadStage}
                    uploadProgress={uploadProgress}
                    disabled={isScanning}
                    error={mediaValidationError}
                  />
                ) : (
                  <>
                    <Input
                      label="Media Public URL"
                      type="url"
                      placeholder="https://storage.cdn.com/samples/voice_sample.wav"
                      value={mediaUrl}
                      onChange={(e) => setMediaUrl(e.target.value)}
                      helperText="Publicly accessible URL to audio (.wav/.mp3) or image (.png/.jpg)"
                      required
                      disabled={isScanning}
                    />
                    <div className="flex items-center gap-3 pt-1">
                      <button
                        type="button"
                        onClick={() => {
                          setMediaUrl('https://raw.githubusercontent.com/CyberGuard/samples/main/synthetic_voice.wav');
                          setMediaType('audio');
                        }}
                        className="text-primary text-[11px] hover:underline"
                      >
                        Sample Audio URL
                      </button>
                      <span className="text-muted-foreground text-xs">•</span>
                      <button
                        type="button"
                        onClick={() => {
                          setMediaUrl('https://raw.githubusercontent.com/CyberGuard/samples/main/deepfake_face.png');
                          setMediaType('image');
                        }}
                        className="text-primary text-[11px] hover:underline"
                      >
                        Sample Image URL
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Action Buttons */}
            <div className="pt-2 flex items-center justify-between gap-3">
              <Button
                type="submit"
                variant="default"
                isLoading={isScanning}
                className="w-full sm:w-auto font-mono text-xs uppercase tracking-wider font-semibold"
                iconRight={ArrowRight}
              >
                {isScanning
                  ? uploadStage === 'REQUESTING_UPLOAD_URL'
                    ? 'Requesting Credentials...'
                    : uploadStage === 'UPLOADING'
                    ? `Uploading (${uploadProgress}%)...`
                    : uploadStage === 'ANALYZING'
                    ? 'Analyzing Media...'
                    : 'Inspecting...'
                  : 'Inspect Threat'}
              </Button>

              {(scanResult || errorMessage || selectedMediaFile) && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleReset}
                  className="text-xs"
                >
                  <RotateCcw className="w-3.5 h-3.5 mr-1" />
                  Clear
                </Button>
              )}
            </div>
          </form>
        </div>

        {/* Right Column: Scan Result Viewport (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          {/* Error Message Notice */}
          {errorMessage && (
            <div className="p-4 rounded-xl bg-destructive/10 border border-destructive/30 text-destructive text-xs space-y-2">
              <div className="flex items-center gap-2 font-semibold">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>Inspection Notice</span>
              </div>
              <p className="leading-relaxed text-destructive/90">{errorMessage}</p>
            </div>
          )}

          {/* Loading Skeleton */}
          {isScanning && (
            <div className="p-6 rounded-xl bg-card border border-border space-y-5 animate-pulse">
              <div className="flex justify-between items-center">
                <div className="w-28 h-6 bg-muted rounded"></div>
                <div className="w-16 h-6 bg-muted rounded"></div>
              </div>
              <div className="w-full h-16 bg-muted/60 rounded"></div>
              <div className="space-y-2">
                <div className="w-32 h-4 bg-muted rounded"></div>
                <div className="w-full h-8 bg-muted/50 rounded"></div>
                <div className="w-full h-8 bg-muted/50 rounded"></div>
              </div>
            </div>
          )}

          {/* Populated Result Card */}
          {!isScanning && scanResult && (
            <div className="p-6 rounded-xl bg-card border border-border space-y-6">
              {/* Header with RiskBadge, Score, Source & Threat Type */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-border">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-muted-foreground uppercase font-semibold">
                      Calibrated Assessment
                    </span>
                    {analyzedFileName && (
                      <span className="text-[10px] font-mono text-muted-foreground bg-muted/60 px-1.5 py-0.5 rounded truncate max-w-[180px]">
                        {analyzedFileName}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2.5">
                    <RiskBadge level={normalizeRisk(scanResult.risk_level)} size="lg" />
                    {scanResult.threat_type && (
                      <Badge variant="outline" className="font-mono text-xs capitalize">
                        {scanResult.threat_type.replace(/_/g, ' ')}
                      </Badge>
                    )}
                  </div>
                </div>

                <div className="text-right space-y-0.5">
                  {scanResult.risk_score != null && (
                    <div>
                      <span className="font-mono text-[10px] uppercase text-muted-foreground block font-semibold">
                        Risk Score
                      </span>
                      <span className="font-mono text-2xl font-bold text-foreground">
                        {scanResult.risk_score}
                        <span className="text-xs text-muted-foreground font-normal">/100</span>
                      </span>
                    </div>
                  )}
                  {scanResult.confidence_score != null && (
                    <span className="font-mono text-[10px] text-muted-foreground block">
                      Confidence: {Math.round(scanResult.confidence_score * 100)}%
                    </span>
                  )}
                </div>
              </div>

              {/* Explanation Section */}
              <div className="space-y-2">
                <h3 className="font-mono text-xs uppercase tracking-wider text-muted-foreground font-semibold">
                  Explanation
                </h3>
                <div className="p-3.5 rounded-lg bg-muted/30 border border-border text-xs leading-relaxed text-foreground">
                  {scanResult.explanation || 'No threat indicators detected in evaluated input.'}
                </div>
              </div>

              {/* Recommended Actions Section */}
              <div className="space-y-2">
                <h3 className="font-mono text-xs uppercase tracking-wider text-muted-foreground font-semibold">
                  Recommended Actions
                </h3>
                {normalizedActions.length > 0 ? (
                  <div className="space-y-2">
                    {normalizedActions.map((act) => (
                      <div
                        key={act.id}
                        className="p-3 rounded-lg border border-border bg-card flex items-start gap-2.5 text-xs"
                      >
                        <CheckCircle2 className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                        <span className="text-foreground leading-snug">{act.action_type}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground italic">
                    No urgent mitigation actions required.
                  </p>
                )}
              </div>

              {/* Optional Forensic Signals if returned */}
              {scanResult.signals && typeof scanResult.signals === 'object' && (
                <div className="pt-3 border-t border-border space-y-2">
                  <h3 className="font-mono text-[11px] uppercase text-muted-foreground font-semibold">
                    Detection Signals
                  </h3>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    {Object.entries(scanResult.signals).map(([k, v]) => (
                      <div key={k} className="p-2 rounded bg-muted/40 border border-border">
                        <span className="text-muted-foreground text-[10px] block uppercase">{k}</span>
                        <span className="text-foreground font-semibold">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Idle / Blank state when no scan performed yet */}
          {!isScanning && !scanResult && !errorMessage && (
            <div className="p-8 rounded-xl bg-card border border-dashed border-border">
              <EmptyState
                icon={Radar}
                title="Ready to Inspect"
                description="Submit message text, a domain, or media file to evaluate threat level and retrieve mitigation actions."
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
