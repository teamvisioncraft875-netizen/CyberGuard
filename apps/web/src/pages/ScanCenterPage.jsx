import React, { useState } from 'react';
import { cn } from '../utils/cn';
import { normalizeRisk } from '../utils/risk';
import { normalizeAction } from '../utils/actions';
import { RiskBadge, Badge, Button, Input, Select, Card, CardContent } from '../components/ui';
import { scanService } from '../services';
import {
  Radar,
  Mail,
  Globe,
  FileImage,
  AlertCircle,
  CheckCircle2,
  RotateCcw,
  Sparkles,
  ArrowRight,
  Shield,
  Layers,
} from 'lucide-react';

export function ScanCenterPage() {
  const [activeTab, setActiveTab] = useState('message'); // 'message' | 'url' | 'media'

  // Form states
  const [messageText, setMessageText] = useState('');
  const [sourceType, setSourceType] = useState('email'); // 'email' | 'sms' | 'social'

  const [targetUrl, setTargetUrl] = useState('');

  const [mediaUrl, setMediaUrl] = useState('');
  const [mediaType, setMediaType] = useState('image'); // 'image' | 'audio'

  // Inspection lifecycle states
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  const handleReset = () => {
    setScanResult(null);
    setErrorMessage(null);
  };

  const handleScan = async (e) => {
    e?.preventDefault();
    setErrorMessage(null);
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
        if (!mediaUrl.trim()) {
          setErrorMessage('Please enter a valid media file URL.');
          setIsScanning(false);
          return;
        }
        result = await scanService.checkMedia({
          file_url: mediaUrl.trim(),
          media_type: mediaType,
        });
      }

      setScanResult(result);
    } catch (err) {
      if (err.status === 429 || err.code === 'RATE_LIMITED') {
        setErrorMessage(
          'Too many scan requests. Rate limit is 100 requests per 15 minutes. Please wait before retrying.'
        );
      } else if (err.status === 502 || err.code === 'DETECTION_ENGINE_UNAVAILABLE') {
        setErrorMessage(
          'Detection engine service is currently unavailable. Please verify the AI/ML inspection service is active.'
        );
      } else {
        setErrorMessage(
          err.message || 'Threat scan failed. Please verify the input payload and gateway connection.'
        );
      }
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
              <>
                <Select
                  label="Media Classification"
                  value={mediaType}
                  onChange={(e) => setMediaType(e.target.value)}
                >
                  <option value="image">Image File (Deepfake / Stego)</option>
                  <option value="audio">Audio Clip (Voice Clone / ASVspoof)</option>
                </Select>

                <Input
                  label="Media Public URL"
                  type="url"
                  placeholder="https://storage.cdn.com/samples/voice_sample.wav"
                  value={mediaUrl}
                  onChange={(e) => setMediaUrl(e.target.value)}
                  helperText="Publicly accessible URL to audio (.wav/.mp3) or image (.png/.jpg)"
                  required
                />
              </>
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
                Inspect Threat
              </Button>

              {(scanResult || errorMessage) && (
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
              {/* Header with RiskBadge, Score & Threat Type */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-border">
                <div className="space-y-1">
                  <span className="font-mono text-[10px] text-muted-foreground uppercase font-semibold">
                    Calibrated Assessment
                  </span>
                  <div className="flex items-center gap-2.5">
                    <RiskBadge level={normalizeRisk(scanResult.risk_level)} size="lg" />
                    {scanResult.threat_type && (
                      <Badge variant="outline" className="font-mono text-xs capitalize">
                        {scanResult.threat_type.replace(/_/g, ' ')}
                      </Badge>
                    )}
                  </div>
                </div>

                {scanResult.risk_score != null && (
                  <div className="text-right">
                    <span className="font-mono text-[10px] uppercase text-muted-foreground block font-semibold">
                      Risk Score
                    </span>
                    <span className="font-mono text-2xl font-bold text-foreground">
                      {scanResult.risk_score}
                      <span className="text-xs text-muted-foreground font-normal">/100</span>
                    </span>
                  </div>
                )}
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
            <div className="p-12 rounded-xl bg-card border border-dashed border-border text-center flex flex-col items-center justify-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-muted flex items-center justify-center text-muted-foreground">
                <Radar className="w-6 h-6" />
              </div>
              <h3 className="font-headline font-semibold text-sm text-foreground">
                Ready to Inspect
              </h3>
              <p className="font-body text-xs text-muted-foreground max-w-xs">
                Submit message text, a domain, or media file to evaluate threat level and retrieve mitigation actions.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
