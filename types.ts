/**
 * CYBERGUARD — Unified TypeScript Interfaces & API Types
 *
 * Authoritative type definitions generated from the backend schemas,
 * database models, and API Gateway endpoints. Use these interfaces across
 * apps/web and apps/mobile to code against the backend API.
 */

// ============================================================================
// 1. ENUMS & LITERAL TYPES
// ============================================================================

export type UserRole = 'individual' | 'employee' | 'admin';

/**
 * Normalized 5-tier calibrated risk levels.
 * Note: Database returns lowercase, while ML service and check endpoints return TitleCase.
 * Helper functions should always normalize to lowercase for comparisons.
 */
export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type RiskLevelTitleCase = 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical';
export type AnyRiskLevel = RiskLevel | RiskLevelTitleCase;

export type ThreatType =
  | 'phishing'
  | 'malicious_url'
  | 'deepfake'
  | 'impersonation'
  | 'account_takeover'
  | 'technical_threat'
  | 'system_anomaly';

export type SourceType =
  | 'email'
  | 'sms'
  | 'social'
  | 'url'
  | 'image'
  | 'audio'
  | 'video'
  | 'login'
  | 'system';

export type IncidentStatus = 'open' | 'investigating' | 'resolved';

export type ActionStatus = 'pending' | 'taken' | 'dismissed';

export type GuardianLinkStatus = 'pending' | 'active' | 'revoked';

export type TelemetryEventType = 'process' | 'network' | 'api';

export type MessageSourceType = 'email' | 'sms' | 'social';

export type MediaType = 'image' | 'audio';

// ============================================================================
// 2. DOMAIN ENTITY MODELS
// ============================================================================

export interface User {
  id: string; // UUIDv4
  email: string;
  full_name?: string;
  role: UserRole;
  organization_id: string | null;
  created_at: string; // ISO 8601
  updated_at?: string; // ISO 8601
}

export interface Organization {
  id: string; // UUIDv4
  name: string;
  domain: string | null;
  created_at: string; // ISO 8601
}

export interface Device {
  id: string; // UUIDv4
  user_id: string;
  device_id: string;
  device_name: string;
  platform: 'desktop' | 'mobile' | 'server';
  device_fingerprint?: string | null;
  is_trusted: boolean;
  last_seen_at: string;
  created_at: string;
}

export interface RecommendedActionEntity {
  id: string;
  incident_id: string;
  action_type: string;
  action_status: ActionStatus;
  created_at: string;
}

export interface MitreMappingEntity {
  id: string;
  incident_id: string;
  technique_id: string; // e.g. "T1566"
  technique_name: string; // e.g. "Phishing"
}

export interface DetectionSignalEntity {
  id?: string;
  incident_id?: string;
  signal_name: string;
  signal_value: string | null;
  weight: number | null;
}

export interface IncidentEvidenceEntity {
  id: string;
  incident_id: string;
  evidence_type: string;
  raw_payload: Record<string, any>;
  file_url: string | null;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface Incident {
  id: string;
  user_id: string | null;
  organization_id: string | null;
  threat_type: ThreatType | string;
  source_type: SourceType | string;
  risk_level: AnyRiskLevel;
  risk_score: number; // 0 to 100
  explanation: string;
  status: IncidentStatus;
  resolved_by: string | null;
  resolved_at: string | null;
  created_at: string;
  recommended_actions?: RecommendedActionEntity[];
  mitre_mappings?: MitreMappingEntity[];
  detection_signals?: DetectionSignalEntity[];
  evidence?: IncidentEvidenceEntity[];
}

export interface GuardianLink {
  link_id: string; // Aliased to id
  id?: string;
  guardian_user_id: string;
  dependent_user_id: string;
  status: GuardianLinkStatus;
  created_at: string;
}

export interface GuardianAlert {
  alert_id: string;
  dependent_user_id: string;
  dependent_name: string;
  risk_level: RiskLevelTitleCase | string;
  threat_type: ThreatType | string;
  explanation: string;
  recommended_action: string;
  timestamp: string;
}

// ============================================================================
// 3. API REQUEST DTOs
// ============================================================================

export interface SignupRequest {
  email: string;
  password: string;
  full_name: string;
  role?: UserRole;
  organization_id?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface CheckMessageRequest {
  text: string;
  source_type: MessageSourceType;
}

export interface CheckUrlRequest {
  url: string;
}

export interface CheckMediaRequest {
  file_url: string;
  media_type: MediaType;
}

export interface ReportLoginEventRequest {
  timestamp: string; // ISO 8601
  device_id: string;
  failed_attempts: number;
  location?: string;
  ip_address?: string;
  user_id?: string; // Admin-only override
}

export interface ReportSystemEventRequest {
  timestamp: string; // ISO 8601
  event_type: string;
  details: Record<string, any>;
  device_id?: string;
  user_id?: string; // Admin-only override
}

export interface UpdateIncidentStatusRequest {
  status: IncidentStatus;
}

export interface UpdateActionStatusRequest {
  action_status: 'taken' | 'dismissed';
}

export interface LinkDependentRequest {
  guardian_user_id: string;
  dependent_user_id: string;
}

export interface IncidentFilterParams {
  limit?: number;
  offset?: number;
  risk_level?: RiskLevel | string;
  status?: IncidentStatus | string;
  threat_type?: ThreatType | string;
  category?: ThreatType | string;
}

// ============================================================================
// 4. API RESPONSE DTOs
// ============================================================================

export interface AuthResponse {
  token: string;
  user: User;
}

export interface CheckResponse {
  id: string;
  risk_level: RiskLevelTitleCase | RiskLevel;
  explanation: string;
  recommended_actions: string[];
  confidence_score?: number;
  signals: Record<string, any>;
}

export interface TelemetryIngestResponse {
  status: 'recorded';
  anomaly_detected: boolean;
  risk_level: RiskLevelTitleCase | RiskLevel;
  risk_score?: number;
  explanation?: string;
  recommended_actions?: string[];
  signals?: Record<string, any>;
  incident_id?: string;
}

export interface PaginatedIncidentsResponse {
  total: number;
  limit: number;
  offset: number;
  incidents: Incident[];
  data: Incident[];
}

export interface UpdateIncidentStatusResponse {
  id: string;
  status: IncidentStatus;
  resolved_by: string;
  updated_at: string;
}

export interface AnalyticsOverviewResponse {
  total_incidents: number;
  active_threats: number;
  resolved_threats: number;
  risk_breakdown: {
    Safe: number;
    Low: number;
    Medium: number;
    High: number;
    Critical: number;
  };
  category_breakdown: {
    phishing: number;
    malicious_url: number;
    deepfake: number;
    account_takeover: number;
    system_anomaly: number;
  };
}

export interface AnalyticsTrendItem {
  date: string; // "YYYY-MM-DD"
  incidents: number;
  high_critical: number;
}

export interface AnalyticsMitreItem {
  technique_id: string; // e.g. "T1566"
  technique_name: string; // e.g. "Phishing"
  incident_count: number;
}

export interface HealthCheckResponse {
  status: 'ok' | 'degraded';
  service: string;
  timestamp?: string;
  uptime?: number;
}

export interface ApiErrorResponse {
  error: string;
  message: string;
}

// ============================================================================
// 5. REAL-TIME WEBSOCKET (SOCKET.IO) TYPES
// ============================================================================

export interface IncidentNewSocketPayload {
  id: string;
  threat_type: ThreatType | string;
  source_type: SourceType | string;
  risk_level: string;
  risk_score: number;
  explanation: string;
  status: IncidentStatus;
  created_at: string;
  recommended_actions: string[];
  signals: Record<string, any>;
}

export interface SubscribeSocketPayload {
  room?: string;
  rooms?: string[];
}

export interface SocketAuthData {
  token: string;
}
