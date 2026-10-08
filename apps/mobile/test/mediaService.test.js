const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { resetSecureStore } = require('./setup');

describe('Media & Deepfake Scanner Service Tests', () => {
  let originalFetch;
  let mediaService;
  let MAX_MEDIA_SIZE_BYTES;

  beforeEach(() => {
    resetSecureStore();
    originalFetch = global.fetch;

    delete require.cache[require.resolve('../src/services/mediaService')];
    delete require.cache[require.resolve('../src/services/apiClient')];

    const mediaMod = require('../src/services/mediaService');
    mediaService = mediaMod.mediaService;
    MAX_MEDIA_SIZE_BYTES = mediaMod.MAX_MEDIA_SIZE_BYTES;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('D1: requestUploadUrl dispatches valid mediaType, fileSizeBytes and fileName', async () => {
    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          upload_url: 'https://storage.supabase.co/signed-url',
          file_path: 'uploads/u-1/test.jpg',
          expiry_seconds: 3600
        })
      };
    };

    const res = await mediaService.requestUploadUrl({
      mediaType: 'image',
      fileSizeBytes: 2048,
      fileName: 'evidence.png'
    });

    assert.strictEqual(capturedBody.media_type, 'image');
    assert.strictEqual(capturedBody.file_size_bytes, 2048);
    assert.strictEqual(capturedBody.file_name, 'evidence.png');
    assert.ok(res.upload_url.includes('signed-url'));
  });

  it('D2: enforces 50 MB client-side file size limit', async () => {
    await assert.rejects(
      async () => {
        await mediaService.requestUploadUrl({
          mediaType: 'image',
          fileSizeBytes: MAX_MEDIA_SIZE_BYTES + 1,
          fileName: 'huge.jpg'
        });
      },
      /exceeds maximum allowed size limit of 50 MB/
    );
  });

  it('D3: rejects invalid media types before dispatching', async () => {
    await assert.rejects(
      async () => {
        await mediaService.requestUploadUrl({
          mediaType: 'video', // Only image and audio are supported
          fileSizeBytes: 1024,
          fileName: 'video.mp4'
        });
      },
      /mediaType must be either 'image' or 'audio'/
    );
  });

  it('D4: scanMedia dispatches filePath and mediaType to /check/media', async () => {
    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          risk_level: 'high',
          explanation: 'AI facial manipulation detected',
          signals: { deepfake_score: 0.94 }
        })
      };
    };

    const res = await mediaService.scanMedia({
      filePath: 'uploads/u-1/face.png',
      mediaType: 'image'
    });

    assert.strictEqual(capturedBody.file_path, 'uploads/u-1/face.png');
    assert.strictEqual(capturedBody.media_type, 'image');
    assert.strictEqual(res.risk_level, 'high');
  });

  it('D5: scanMedia rejects missing file_path', async () => {
    await assert.rejects(
      async () => {
        await mediaService.scanMedia({
          filePath: '',
          mediaType: 'image'
        });
      },
      /Valid storage file_path is required/
    );
  });
});
