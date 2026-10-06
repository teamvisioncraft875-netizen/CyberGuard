const streamingService = require('./streamingService');

/**
 * Performance Metrics Service — Real-time telemetry, SLA monitoring & benchmark tracking
 * for SIEM ingestion, correlation execution, API latencies, and streaming throughput.
 */
class PerformanceMetricsService {
  constructor() {
    this.WINDOW_SIZE = 1000; // Keep up to 1000 sample points per ring buffer

    // Ingestion latency samples [ms]
    this.ingestionSamples = [];
    this.totalIngestedEvents = 0;
    this.ingestionWindowStart = Date.now();

    // Detection latency samples [ms]
    this.detectionSamples = [];
    this.totalDetectionsEvaluated = 0;

    // API response time samples { route, durationMs, timestamp }
    this.apiSamples = [];
    this.slowQueries = []; // > 100ms

    // Streaming throughput counter
    this.messagesPublished = 0;
    this.streamWindowStart = Date.now();

    // Historical 1-minute buckets
    this.historyBuckets = [];
  }

  /**
   * Records batch or event ingestion latency
   */
  recordIngestion(count = 1, durationMs = 0) {
    const validCount = Math.max(1, parseInt(count, 10) || 1);
    this.totalIngestedEvents += validCount;

    this.ingestionSamples.push(durationMs);
    if (this.ingestionSamples.length > this.WINDOW_SIZE) {
      this.ingestionSamples.shift();
    }
  }

  /**
   * Records detection / correlation execution latency
   */
  recordDetection(durationMs = 0) {
    this.totalDetectionsEvaluated++;
    this.detectionSamples.push(durationMs);
    if (this.detectionSamples.length > this.WINDOW_SIZE) {
      this.detectionSamples.shift();
    }
  }

  /**
   * Records API endpoint latency and tracks slow queries (> 100ms)
   */
  recordApiLatency(route, durationMs = 0) {
    this.apiSamples.push({ route, durationMs, timestamp: Date.now() });
    if (this.apiSamples.length > this.WINDOW_SIZE) {
      this.apiSamples.shift();
    }

    if (durationMs > 100) {
      this.slowQueries.push({ route, durationMs, timestamp: new Date().toISOString() });
      if (this.slowQueries.length > 100) {
        this.slowQueries.shift();
      }
    }
  }

  /**
   * Records streaming message dispatch
   */
  recordStreamMessage(count = 1) {
    this.messagesPublished += count;
  }

  /**
   * Helper to compute percentile from array
   */
  _computePercentile(arr, p) {
    if (!arr || arr.length === 0) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const index = Math.ceil((p / 100) * sorted.length) - 1;
    return parseFloat(sorted[Math.max(0, index)].toFixed(2));
  }

  /**
   * Helper to compute average from array
   */
  _computeAverage(arr) {
    if (!arr || arr.length === 0) return 0;
    const sum = arr.reduce((acc, val) => acc + val, 0);
    return parseFloat((sum / arr.length).toFixed(2));
  }

  /**
   * Gets current real-time performance summary
   */
  getSummary(organizationId = null) {
    const now = Date.now();
    const elapsedIngestSec = Math.max(1, (now - this.ingestionWindowStart) / 1000);
    const eventsPerSecond = parseFloat((this.totalIngestedEvents / elapsedIngestSec).toFixed(2));

    const elapsedStreamSec = Math.max(1, (now - this.streamWindowStart) / 1000);
    const messagesPerSecond = parseFloat((this.messagesPublished / elapsedStreamSec).toFixed(2));

    const activeSubscribers = streamingService.getActiveStreamCount(organizationId);

    return {
      events_per_second: eventsPerSecond,
      avg_ingestion_ms: this._computeAverage(this.ingestionSamples),
      p95_ingestion_ms: this._computePercentile(this.ingestionSamples, 95),
      p99_ingestion_ms: this._computePercentile(this.ingestionSamples, 99),
      active_subscribers: activeSubscribers,
      avg_detection_ms: this._computeAverage(this.detectionSamples),
      p95_detection_ms: this._computePercentile(this.detectionSamples, 95),
      total_detections_evaluated: this.totalDetectionsEvaluated,
      messages_per_second: messagesPerSecond,
      slow_queries_count: this.slowQueries.length
    };
  }

  /**
   * Returns history snapshots of performance metrics
   */
  getHistory(organizationId = null, limit = 60) {
    const current = this.getSummary(organizationId);
    return {
      current,
      recent_slow_queries: this.slowQueries.slice(-20)
    };
  }

  /**
   * Resets metrics counters (for test suites)
   */
  reset() {
    this.ingestionSamples = [];
    this.totalIngestedEvents = 0;
    this.ingestionWindowStart = Date.now();
    this.detectionSamples = [];
    this.totalDetectionsEvaluated = 0;
    this.apiSamples = [];
    this.slowQueries = [];
    this.messagesPublished = 0;
    this.streamWindowStart = Date.now();
  }
}

// Singleton export
const performanceMetricsService = new PerformanceMetricsService();
module.exports = performanceMetricsService;
