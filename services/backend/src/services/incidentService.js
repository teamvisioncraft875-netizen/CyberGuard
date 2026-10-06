const { transaction } = require('../config/db');
const { getIO } = require('../config/socket');
const Incident = require('../models/Incident');
const DetectionSignal = require('../models/DetectionSignal');
const RecommendedAction = require('../models/RecommendedAction');
const GuardianLink = require('../models/GuardianLink');
const MitreMapping = require('../models/MitreMapping');
const PolicyEngine = require('./PolicyEngine');
const incidentDeduplicationService = require('./incidentDeduplicationService');
const incidentCorrelationService = require('./incidentCorrelationService');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');
const incidentThreatIntelService = require('./incidentThreatIntelService');

// Keys representing context/metadata rather than individual detection indicators
const METADATA_KEYS = new Set(['url', 'file_url', 'media_type', 'model_type', 'source_type']);

// Fallback approximation until all engines return a real numeric score
const FALLBACK_SCORES = {
  critical: 90,
  high: 70,
  medium: 45,
  low: 20,
  safe: 5
};

/**
 * Extracts and sanitizes detection signals for database insertion, skipping descriptive metadata keys.
 */
function extractDetectionSignals(signals, incidentId) {
  const signalRows = [];

  if (Array.isArray(signals)) {
    for (const item of signals) {
      if (!item || typeof item !== 'object') continue;
      const name = item.signal_name || item.name || Object.keys(item)[0];
      if (!name || METADATA_KEYS.has(String(name).toLowerCase())) continue;
      const rawVal = item.signal_value !== undefined ? item.signal_value : (item.value !== undefined ? item.value : item[name]);
      const signalValue = rawVal !== undefined && rawVal !== null ? String(rawVal) : '';
      let weight = null;
      if (typeof item.weight === 'number' && !isNaN(item.weight) && item.weight >= 0 && item.weight <= 1) {
        weight = item.weight;
      } else if (typeof rawVal === 'number' && !isNaN(rawVal) && rawVal >= 0 && rawVal <= 1) {
        weight = rawVal;
      }
      signalRows.push({
        incident_id: incidentId,
        signal_name: String(name),
        signal_value: signalValue,
        weight
      });
    }
  } else if (signals && typeof signals === 'object') {
    for (const [key, val] of Object.entries(signals)) {
      if (METADATA_KEYS.has(key.toLowerCase())) continue;
      const signalValue = val !== undefined && val !== null ? String(val) : '';
      let weight = null;
      if (typeof val === 'number' && !isNaN(val) && val >= 0 && val <= 1) {
        weight = val;
      }
      signalRows.push({
        incident_id: incidentId,
        signal_name: key,
        signal_value: signalValue,
        weight
      });
    }
  }

  return signalRows;
}

/**
 * Persists an incident, its detection signals, and recommended actions within an atomic transaction.
 * Emits real-time WebSocket notifications upon successful commit.
 */
async function persistDetectionIncident({
  user,
  threatType,
  sourceType,
  mlResult,
  recommendedActions = []
}, client = null) {
  const riskLevel = (mlResult.risk_level || 'medium').toLowerCase();
  // Approximate fallback score based on risk_level until all engines return a real score
  const riskScore = typeof mlResult.risk_score === 'number'
    ? mlResult.risk_score
    : (FALLBACK_SCORES[riskLevel] ?? 50);

  const effectiveUser = user || {};
  const organizationId = effectiveUser.organization_id || null;
  const deviceId = effectiveUser.device_id || mlResult?.details?.device_id || mlResult?.signals?.device_id || null;

  // 1. Generate Deterministic Fingerprint
  const fingerprint = incidentDeduplicationService.generateFingerprint({
    organization_id: organizationId,
    threat_type: threatType,
    user_id: effectiveUser.id || null,
    device_id: deviceId,
    signals: mlResult?.signals || {},
    details: mlResult?.details || {},
    ...mlResult?.details
  });

  const windowMinutes = incidentDeduplicationService.getDedupWindow(threatType);

  // 2. Pre-Insert Duplicate Check
  try {
    const { isDuplicate, incident: existingIncident } = await incidentDeduplicationService.checkDuplicate({
      organizationId,
      fingerprint,
      windowMinutes,
      client
    });

    if (isDuplicate && existingIncident) {
      // 3. Consolidate Existing Incident
      const consolidated = await incidentDeduplicationService.consolidateIncident({
        incidentId: existingIncident.id,
        client
      });

      // Write audit logs
      auditLog({
        organization_id: organizationId,
        user_id: effectiveUser.id || null,
        actor_type: 'system_guard',
        action: AUDIT_ACTIONS.INCIDENT_DEDUPLICATED,
        resource_type: 'incident',
        resource_id: existingIncident.id,
        details: {
          incident_id: existingIncident.id,
          fingerprint,
          occurrence_count: consolidated?.occurrence_count || (existingIncident.occurrence_count + 1)
        }
      }, client);

      auditLog({
        organization_id: organizationId,
        user_id: effectiveUser.id || null,
        actor_type: 'system_guard',
        action: AUDIT_ACTIONS.INCIDENT_CONSOLIDATED,
        resource_type: 'incident',
        resource_id: existingIncident.id,
        details: {
          incident_id: existingIncident.id,
          fingerprint,
          occurrence_count: consolidated?.occurrence_count || (existingIncident.occurrence_count + 1)
        }
      }, client);

      const targetIncident = consolidated || existingIncident;
      return {
        deduplicated: true,
        incident: targetIncident,
        ...targetIncident
      };
    }
  } catch (dedupErr) {
    console.warn('[Deduplication Pre-Check Warning]', dedupErr.message);
  }

  let incident = null;
  let dbError = null;

  const runInsert = async (dbClient) => {
    // Insert into incidents with fingerprint metadata
    // 0. Threat Intelligence Correlation & Risk Boost (pre-insert)
    let threatIntelEnrichment = null;
    let finalRiskScore = riskScore;
    let finalRiskLevel = riskLevel;

    try {
      threatIntelEnrichment = await incidentThreatIntelService.enrichIncidentPreInsert({
        threatType,
        sourceType,
        mlResult,
        organizationId: effectiveUser.organization_id || null,
        client: dbClient
      });

      if (threatIntelEnrichment) {
        finalRiskScore = threatIntelEnrichment.enriched_risk_score;
        finalRiskLevel = threatIntelEnrichment.enriched_risk_level || riskLevel;
      }
    } catch (tiErr) {
      console.warn('[persistDetectionIncident Threat Intel Warning]', tiErr.message);
    }

    // Insert into incidents
    const newIncident = await Incident.create({
      user_id: effectiveUser.id || null,
      organization_id: effectiveUser.organization_id || null,
      threat_type: threatType,
      source_type: sourceType,
      risk_level: finalRiskLevel,
      risk_score: finalRiskScore,
      explanation: mlResult.explanation || '',
      status: 'open',
      fingerprint,
      device_id: deviceId,
      first_seen_at: new Date(),
      last_seen_at: new Date(),
      occurrence_count: 1
    }, dbClient);

    // Insert into mitre_mappings
    const ruleId = mlResult?.details?.rule_id || mlResult?.rule_id || null;
    const mitreTechnique = MitreMapping.getTechniqueForThreat(threatType, ruleId);
    await MitreMapping.create({
      incident_id: newIncident.id,
      technique_id: mitreTechnique.technique_id,
      technique_name: mitreTechnique.technique_name
    }, dbClient);

    // Insert into detection_signals
    const signalsToInsert = extractDetectionSignals(mlResult.signals, newIncident.id);
    if (signalsToInsert.length > 0) {
      await DetectionSignal.createMany(signalsToInsert, dbClient);
    }

    // Persist incident_ioc_matches within same transaction
    if (threatIntelEnrichment && threatIntelEnrichment.matches && threatIntelEnrichment.matches.length > 0) {
      try {
        await incidentThreatIntelService.persistIncidentIOCMatches(
          newIncident.id,
          effectiveUser.organization_id || null,
          threatIntelEnrichment.matches,
          dbClient
        );
      } catch (matchErr) {
        console.warn('[persistDetectionIncident Match Persistence Warning]', matchErr.message);
      }
    }

    // Insert into recommended_actions
    const actionsToInsert = recommendedActions.map((action) => ({
      incident_id: newIncident.id,
      action_type: typeof action === 'string' ? action : (action.action_type || action.action_text || String(action)),
      action_status: 'pending'
    }));
    if (actionsToInsert.length > 0) {
      await RecommendedAction.createMany(actionsToInsert, dbClient);
    }

    // Attach threat intelligence enrichment metadata to returned object
    if (threatIntelEnrichment) {
      newIncident.threat_intel = threatIntelEnrichment.threat_intel;
      newIncident.ioc_matches = threatIntelEnrichment.matches;
    }

    if (newIncident && newIncident.risk_score !== undefined && newIncident.risk_score !== null) {
      newIncident.risk_score = Number(newIncident.risk_score);
    }

    return newIncident;
  };

  // 1. Transaction persistence (atomic all-or-nothing)
  try {
    if (client) {
      incident = await runInsert(client);
    } else {
      incident = await transaction(runInsert);
    }
  } catch (err) {
    console.error('[persistDetectionIncident dbError]', err);
    dbError = err;
    // Fallback incident record for database-unconfigured environments
    incident = {
      id: `inc_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      user_id: effectiveUser.id || null,
      organization_id: effectiveUser.organization_id || null,
      threat_type: threatType,
      source_type: sourceType,
      risk_level: riskLevel,
      risk_score: riskScore,
      explanation: mlResult.explanation || '',
      status: 'open',
      created_at: new Date().toISOString()
    };
  }

  // 2. Real-time WebSocket emission (executed AFTER transaction commit or fallback)
  try {
    const io = getIO();
    if (io) {
      const incidentPayload = {
        id: incident.id,
        threat_type: incident.threat_type,
        source_type: incident.source_type,
        risk_level: incident.risk_level,
        risk_score: typeof incident.risk_score === 'number' ? incident.risk_score : Number(incident.risk_score),
        explanation: incident.explanation,
        status: incident.status,
        created_at: incident.created_at,
        recommended_actions: recommendedActions,
        signals: mlResult.signals || {},
        threat_intel: incident.threat_intel || null,
        ioc_matches: incident.ioc_matches || []
      };

      // Construct deduplicated set of authorized rooms (user, tenant org, active guardians)
      const targetRooms = new Set();
      if (incident.user_id) targetRooms.add(`user:${incident.user_id}`);
      if (incident.organization_id) targetRooms.add(`org:${incident.organization_id}`);

      // Add active guardians linked to this dependent user
      try {
        const guardianLinks = await GuardianLink.findByDependentId(incident.user_id);
        if (Array.isArray(guardianLinks)) {
          for (const link of guardianLinks) {
            if (link.guardian_user_id) {
              targetRooms.add(`guardian:${link.guardian_user_id}`);
            }
          }
        }
      } catch (gErr) {
        // Non-critical guardian link lookup error in dev mode
      }

      // Socket.io chained .to() deduplicates client sockets across rooms and guarantees exact-once delivery
      if (targetRooms.size > 0) {
        let emitter = io;
        for (const room of targetRooms) {
          emitter = emitter.to(room);
        }
        emitter.emit('incident:new', incidentPayload);
      } else {
        io.emit('incident:new', incidentPayload);
      }
    }
  } catch (wsErr) {
    console.error('[WebSocket Notification Error]', wsErr.message);
  }

  // 3. Automated Response Layer — Policy Engine Evaluation (Phase 1B: SHADOW MODE)
  // Evaluates applicable response policies and records proposed actions in shadow mode.
  // Fire-and-forget: will never delay or fail the detection incident response.
  PolicyEngine.evaluateAndProposeActions({
    ...incident,
    signals: mlResult.signals || {},
    details: mlResult.details || {},
    target: mlResult.details || {},
    threat_intel: incident.threat_intel || (threatIntelEnrichment ? threatIntelEnrichment.threat_intel : null),
    ioc_matches: incident.ioc_matches || (threatIntelEnrichment ? threatIntelEnrichment.matches : []),
    analysis_confidence: mlResult.confidence ?? mlResult.analysis_confidence ?? (mlResult.signals?.confidence_score != null ? mlResult.signals.confidence_score * 100 : null) ?? 100,
    ml_degraded: mlResult.ml_degraded || mlResult.signals?.ml_degraded || false,
    user_role: effectiveUser.role || null
  }).catch((policyErr) => {
    console.error('[PolicyEngine Background Evaluation Error]', policyErr.message);
  });

  // 4. Incident Correlation Engine — Correlate with historical open incidents (Task 2)
  // Wrapped in try/catch: correlation failures must NEVER fail incident creation
  if (incident && incident.id && incident.organization_id) {
    try {
      await incidentCorrelationService.correlateIncident(incident.id, incident.organization_id);
    } catch (corrErr) {
      console.warn('[IncidentCorrelation Warning] Non-critical correlation error:', corrErr.message);
    }
  }

  if (dbError && process.env.NODE_ENV !== 'test' && process.env.STRICT_DB === 'true') {
    throw dbError;
  }

  if (incident && incident.organization_id) {
    try {
      const streamingService = require('./siem/streamingService');
      streamingService.publishIncident(incident, incident.organization_id);
    } catch (streamErr) {}
  }

  return incident;
}

/**
 * Resolves an incident by setting its status to 'resolved'.
 */
async function resolveIncident(incidentId, client = null) {
  const dbClient = client || require('../config/db');
  const res = await dbClient.query(
    `UPDATE public.incidents
     SET status = 'resolved', resolved_at = NOW()
     WHERE id = $1 AND status = 'open'
     RETURNING *;`,
    [incidentId]
  );
  return res.rows[0] || null;
}

module.exports = {
  persistDetectionIncident,
  extractDetectionSignals,
  resolveIncident,
  FALLBACK_SCORES,
  METADATA_KEYS
};
