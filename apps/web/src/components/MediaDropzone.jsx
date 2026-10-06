import React, { useRef, useState, useEffect } from 'react';
import { cn } from '../utils/cn';
import { formatBytes } from '../utils/format';
import { Badge, Button } from './ui';
import {
  UploadCloud,
  FileImage,
  FileAudio,
  X,
  AlertCircle,
  CheckCircle2,
  Loader2,
} from 'lucide-react';

export const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB

export const ALLOWED_EXTENSIONS = Object.freeze({
  image: ['jpg', 'jpeg', 'png', 'webp', 'gif'],
  audio: ['wav', 'mp3', 'ogg', 'flac', 'm4a'],
});

const ACCEPT_STRING = [
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
  'audio/wav',
  'audio/mpeg',
  'audio/mp3',
  'audio/ogg',
  'audio/flac',
  'audio/x-m4a',
  'audio/m4a',
  '.jpg',
  '.jpeg',
  '.png',
  '.webp',
  '.gif',
  '.wav',
  '.mp3',
  '.ogg',
  '.flac',
  '.m4a',
].join(',');

/**
 * Detects whether a file is an image or audio based on extension and MIME type.
 * Returns 'image' | 'audio' | null
 */
export function detectMediaType(file) {
  if (!file) return null;
  const name = file.name || '';
  const ext = name.split('.').pop()?.toLowerCase();

  if (ALLOWED_EXTENSIONS.image.includes(ext) || file.type?.startsWith('image/')) {
    return 'image';
  }
  if (ALLOWED_EXTENSIONS.audio.includes(ext) || file.type?.startsWith('audio/')) {
    return 'audio';
  }
  return null;
}

/**
 * Validates a file against allowed types and maximum size constraints.
 * Returns { valid: boolean, error?: string, mediaType?: 'image' | 'audio' }
 */
export function validateMediaFile(file) {
  if (!file) {
    return { valid: false, error: 'No file selected.' };
  }

  if (file.size <= 0) {
    return {
      valid: false,
      error: 'Selected file is empty (0 bytes). Please choose a valid media file.',
    };
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    return {
      valid: false,
      error: `File size exceeds the 50MB limit (${formatBytes(file.size)}). Please choose a smaller file.`,
    };
  }

  const detected = detectMediaType(file);
  if (!detected) {
    return {
      valid: false,
      error:
        'Unsupported file format. Please upload an image (.png, .jpg, .jpeg, .webp, .gif) or audio (.wav, .mp3, .ogg, .flac, .m4a) file.',
    };
  }

  return { valid: true, mediaType: detected };
}

/**
 * MediaDropzone Component
 * Supports drag-and-drop, client-side validation, live image previews,
 * and upload/analysis progress visualization.
 */
export function MediaDropzone({
  file,
  onFileSelect,
  onFileRemove,
  uploadStage = 'IDLE', // 'IDLE' | 'FILE_SELECTED' | 'VALIDATING' | 'REQUESTING_UPLOAD_URL' | 'UPLOADING' | 'ANALYZING' | 'RESULT' | 'ERROR'
  uploadProgress = 0,
  disabled = false,
  error = null,
}) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [previewUrl, setPreviewUrl] = useState(null);
  const inputRef = useRef(null);

  // Generate and cleanup object URLs for image preview safely
  useEffect(() => {
    if (!file) {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
        setPreviewUrl(null);
      }
      return;
    }

    const detected = detectMediaType(file);
    if (detected === 'image') {
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
      return () => {
        URL.revokeObjectURL(url);
      };
    } else {
      setPreviewUrl(null);
    }
  }, [file]);

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (disabled) return;
    setIsDragOver(true);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (disabled) return;
    setIsDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (disabled) return;

    const droppedFiles = e.dataTransfer?.files;
    if (droppedFiles && droppedFiles.length > 0) {
      processSelectedFile(droppedFiles[0]);
    }
  };

  const handleInputChange = (e) => {
    const selectedFiles = e.target?.files;
    if (selectedFiles && selectedFiles.length > 0) {
      processSelectedFile(selectedFiles[0]);
    }
  };

  const processSelectedFile = (selectedFile) => {
    const validation = validateMediaFile(selectedFile);
    if (!validation.valid) {
      onFileSelect?.(null, null, validation.error);
      return;
    }
    onFileSelect?.(selectedFile, validation.mediaType, null);
  };

  const handleBrowseClick = () => {
    if (disabled) return;
    inputRef.current?.click();
  };

  const isBusy =
    uploadStage === 'VALIDATING' ||
    uploadStage === 'REQUESTING_UPLOAD_URL' ||
    uploadStage === 'UPLOADING' ||
    uploadStage === 'ANALYZING';

  return (
    <div className="space-y-3 w-full font-sans">
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPT_STRING}
        onChange={handleInputChange}
        className="hidden"
        disabled={disabled || isBusy}
      />

      {/* Dropzone Area when no file selected */}
      {!file ? (
        <div
          onDragEnter={handleDragEnter}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={handleBrowseClick}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              handleBrowseClick();
            }
          }}
          className={cn(
            'group relative flex flex-col items-center justify-center p-8 rounded-xl border-2 border-dashed transition-all duration-200 cursor-pointer text-center select-none outline-none focus-visible:ring-2 focus-visible:ring-primary',
            isDragOver
              ? 'border-primary bg-primary/10 scale-[1.005]'
              : 'border-border bg-card/60 hover:bg-muted/40 hover:border-primary/50',
            disabled && 'opacity-60 pointer-events-none'
          )}
        >
          <div className="w-12 h-12 rounded-full bg-primary/10 text-primary flex items-center justify-center mb-3 transition-transform group-hover:scale-110">
            <UploadCloud className="w-6 h-6" />
          </div>

          <p className="text-sm font-semibold text-foreground mb-1">
            Drag & drop media file here, or{' '}
            <span className="text-primary underline-offset-2 hover:underline">browse</span>
          </p>

          <p className="text-xs text-muted-foreground max-w-sm leading-relaxed mb-3">
            Upload voice clips or image portraits to detect deepfake synthesis, face swapping, and voice cloning artifacts.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-1.5 text-[11px] font-mono text-muted-foreground/80">
            <span className="px-2 py-0.5 rounded bg-muted/80 border border-border">PNG, JPG, WEBP, GIF</span>
            <span>•</span>
            <span className="px-2 py-0.5 rounded bg-muted/80 border border-border">WAV, MP3, OGG, FLAC</span>
            <span>•</span>
            <span className="px-2 py-0.5 rounded bg-muted/80 border border-border">Max 50MB</span>
          </div>
        </div>
      ) : (
        /* Selected File Card */
        <div className="p-4 rounded-xl bg-card border border-border space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              {/* Thumbnail or Audio/File Icon */}
              {previewUrl ? (
                <img
                  src={previewUrl}
                  alt="Selected preview"
                  className="w-12 h-12 rounded-lg object-cover border border-border shrink-0 bg-black/20"
                />
              ) : detectMediaType(file) === 'audio' ? (
                <div className="w-12 h-12 rounded-lg bg-primary/15 text-primary flex items-center justify-center shrink-0 border border-primary/20">
                  <FileAudio className="w-6 h-6" />
                </div>
              ) : (
                <div className="w-12 h-12 rounded-lg bg-muted text-foreground flex items-center justify-center shrink-0 border border-border">
                  <FileImage className="w-6 h-6" />
                </div>
              )}

              {/* File Info */}
              <div className="min-w-0 space-y-0.5">
                <div className="flex items-center gap-2">
                  <p className="text-xs font-semibold text-foreground truncate max-w-xs sm:max-w-md" title={file.name}>
                    {file.name}
                  </p>
                  <Badge variant="outline" className="font-mono text-[10px] uppercase shrink-0">
                    {detectMediaType(file) || 'media'}
                  </Badge>
                </div>
                <p className="text-[11px] font-mono text-muted-foreground">
                  {formatBytes(file.size)} • {file.type || 'binary/stream'}
                </p>
              </div>
            </div>

            {/* Remove / Change button */}
            {!isBusy && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={onFileRemove}
                disabled={disabled}
                className="h-8 px-2 text-muted-foreground hover:text-destructive shrink-0"
                title="Remove selected file"
              >
                <X className="w-4 h-4" />
                <span className="sr-only">Remove</span>
              </Button>
            )}
          </div>

          {/* Progress / Status Visualization */}
          {isBusy && (
            <div className="space-y-2 pt-2 border-t border-border">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="flex items-center gap-2 text-foreground font-medium">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-primary" />
                  {uploadStage === 'VALIDATING' && 'Validating payload constraints...'}
                  {uploadStage === 'REQUESTING_UPLOAD_URL' && 'Generating secure signed upload URL...'}
                  {uploadStage === 'UPLOADING' && `Uploading file to storage (${uploadProgress}%)...`}
                  {uploadStage === 'ANALYZING' && 'Running AI deepfake artifact detection...'}
                </span>
                <span className="text-muted-foreground font-semibold">
                  {uploadStage === 'UPLOADING' ? `${uploadProgress}%` : 'In progress'}
                </span>
              </div>

              {/* Progress Bar */}
              <div className="w-full h-1.5 rounded-full bg-muted overflow-hidden relative">
                {uploadStage === 'UPLOADING' ? (
                  <div
                    className="h-full bg-primary transition-all duration-150 ease-out"
                    style={{ width: `${Math.max(5, uploadProgress)}%` }}
                  />
                ) : (
                  <div className="h-full bg-primary/80 animate-pulse w-full" />
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Validation or Upload Error Banner */}
      {error && (
        <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-destructive text-xs flex items-start gap-2">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold block">File Validation Notice</span>
            <p className="leading-relaxed text-destructive/90">{error}</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default MediaDropzone;
