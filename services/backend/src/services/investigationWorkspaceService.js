const db = require('../config/db');
const IncidentNote = require('../models/IncidentNote');
const AttackChainSnapshot = require('../models/AttackChainSnapshot');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

/**
 * Incident Investigation Workspace Service
 *
 * Assembles unified investigation workspace context:
 * - Incident details
 * - Consolidated chronological timeline
 * - Analyst notes
 * - Detection signals
 * - IOC history
 * - Correlation history
 * - Group/Campaign history
 * - Attack chain progression history
 * - Audit trail
 */
class InvestigationWorkspaceService {
  /**
   * Add an analyst note to an incident
   */
  async addNote(incidentId, organizationId, { userId, note }) {
    if (!note || !note.trim()) {
      throw new Error('Note content cannot be empty');
    }

    // Verify incident exists and belongs to organization
    const incRes = await db.query(
      `SELECT id FROM public.incidents WHERE id = $1 AND organization_id = $2;`,
      [incidentId, organizationId]
    );

    if (incRes.rows.length === 0) {
      throw new Error(`Incident ${incidentId} not found in organization ${organizationId}`);
    }

    const created = await IncidentNote.create({
      organization_id: organizationId,
      incident_id: incidentId,
      user_id: userId,
      note: note.trim()
    });

    try {
      require('./commandCenterService').invalidateCache(incidentId);
    } catch {}

    return created;
  }

  /**
   * Assemble full investigation workspace
   */
  async getWorkspace(incidentId, organizationId, { actorUserId = null } = {}) {
    // 1. Fetch incident record with strict tenant isolation
    const incRes = await db.query(
      `SELECT 
        i.*,
        u.email as assigned_user_email,
        d.device_name,
        d.hostname as device_hostname,
        d.platform as device_platform
       FROM public.incidents i
       LEFT JOIN public.users u ON u.id = i.assigned_to
       LEFT JOIN public.devices d ON d.id = i.device_id
       WHERE i.id = $1 AND i.organization_id = $2;`,
      [incidentId, organizationId]
    );

    if (incRes.rows.length === 0) {
      return null;
    }

    const incident = incRes.rows[0];

    // 2. Parallel queries for timeline components
    const [notes, signalsRes, iocsRes, correlationsRes, groupsRes, attackChain, auditsRes] = await Promise.all([
      IncidentNote.findByIncident(incidentId, organizationId),
      db.query(`SELECT * FROM public.detection_signals WHERE incident_id = $1;`, [incidentId]),
      db.query(
        `SELECT * FROM public.incident_ioc_matches
         WHERE incident_id = $1 AND organization_id = $2
         ORDER BY matched_at ASC;`,
        [incidentId, organizationId]
      ),
      db.query(
        `SELECT ir.*,
                CASE WHEN ir.source_incident_id = $1 THEN ir.target_incident_id ELSE ir.source_incident_id END as related_incident_id,
                rel_inc.threat_type as related_threat_type,
                rel_inc.risk_level as related_risk_level
         FROM public.incident_relationships ir
         LEFT JOIN public.incidents rel_inc ON rel_inc.id = CASE WHEN ir.source_incident_id = $1 THEN ir.target_incident_id ELSE ir.source_incident_id END
         WHERE (ir.source_incident_id = $1 OR ir.target_incident_id = $1)
           AND ir.organization_id = $2
         ORDER BY ir.created_at ASC;`,
        [incidentId, organizationId]
      ),
      db.query(
        `SELECT ig.*, igm.joined_at, igm.confidence as membership_confidence
         FROM public.incident_group_members igm
         JOIN public.incident_groups ig ON ig.id = igm.group_id
         WHERE igm.incident_id = $1 AND ig.organization_id = $2;`,
        [incidentId, organizationId]
      ),
      AttackChainSnapshot.findByIncident(incidentId).catch(() => null),
      db.query(
        `SELECT * FROM public.audit_logs
         WHERE resource_id = $1 AND organization_id = $2
         ORDER BY created_at ASC;`,
        [incidentId, organizationId]
      )
    ]);

    const signals = signalsRes.rows;
    const iocs = iocsRes.rows;
    const correlations = correlationsRes.rows;
    const groups = groupsRes.rows;
    const audits = auditsRes.rows;

    // 3. Synthesize unified timeline items
    const timeline = [];

    // Initial detection / first seen
    timeline.push({
      id: `incident-created-${incident.id}`,
      event_type: 'incident_created',
      timestamp: incident.first_seen_at || incident.created_at,
      title: 'Incident First Detected',
      description: incident.explanation || `Detected threat: ${incident.threat_type} (${incident.source_type})`,
      severity: incident.risk_level,
      data: {
        threat_type: incident.threat_type,
        source_type: incident.source_type,
        risk_score: incident.risk_score,
        risk_level: incident.risk_level,
        priority: incident.priority
      }
    });

    // Signals
    signals.forEach(sig => {
      timeline.push({
        id: `sig-${sig.id}`,
        event_type: 'detection_signal',
        timestamp: incident.first_seen_at || incident.created_at,
        title: `Detection Signal: ${sig.signal_name}`,
        description: `Signal value: ${sig.signal_value} (weight: ${sig.weight})`,
        severity: incident.risk_level,
        data: sig
      });
    });

    // IOC Matches
    iocs.forEach(ioc => {
      timeline.push({
        id: `ioc-${ioc.id}`,
        event_type: 'ioc_matched',
        timestamp: ioc.matched_at || incident.created_at,
        title: `Threat Intel IOC Matched: ${ioc.matched_value}`,
        description: `Severity: ${ioc.severity || 'high'}, Source: ${ioc.feed_source || 'AlienVault/OTX'}, Reputation: ${ioc.reputation_score || 0}`,
        severity: ioc.severity || 'high',
        data: ioc
      });
    });

    // Correlations
    correlations.forEach(rel => {
      timeline.push({
        id: `corr-${rel.id}`,
        event_type: 'correlation_linked',
        timestamp: rel.created_at,
        title: `Correlated with Incident: ${rel.related_incident_id}`,
        description: `Correlation rule: ${rel.rule_id} (${rel.relationship_type}) with confidence ${rel.confidence_score}`,
        severity: rel.related_risk_level || 'medium',
        data: rel
      });
    });

    // Groups / Campaigns
    groups.forEach(grp => {
      timeline.push({
        id: `grp-${grp.id}`,
        event_type: 'group_assigned',
        timestamp: grp.joined_at || grp.created_at,
        title: `Clustered into Campaign: ${grp.title}`,
        description: grp.description || `Group type: ${grp.group_type}, Severity: ${grp.severity}`,
        severity: grp.severity || 'high',
        data: grp
      });
    });

    // Attack Chain snapshot timeline
    if (attackChain && Array.isArray(attackChain.timeline)) {
      attackChain.timeline.forEach((step, idx) => {
        timeline.push({
          id: `chain-step-${idx}-${step.incident_id || incident.id}`,
          event_type: 'attack_chain_step',
          timestamp: step.timestamp || attackChain.created_at,
          title: `MITRE Stage: ${step.tactic || step.technique_id || 'Progression'}`,
          description: step.description || `Attack chain stage ${step.stage_index || idx + 1}`,
          severity: 'high',
          data: step
        });
      });
    }

    // Notes
    notes.forEach(n => {
      timeline.push({
        id: `note-${n.id}`,
        event_type: 'analyst_note',
        timestamp: n.created_at,
        title: `Analyst Note by ${n.author_name || n.author_email || 'Analyst'}`,
        description: n.note,
        severity: 'info',
        data: n
      });
    });

    // Audits
    audits.forEach(a => {
      timeline.push({
        id: `audit-${a.id}`,
        event_type: 'audit_event',
        timestamp: a.created_at,
        title: `Action: ${a.action}`,
        description: typeof a.details === 'object' ? JSON.stringify(a.details) : String(a.details || ''),
        severity: 'info',
        data: a
      });
    });

    // Sort chronologically ascending
    timeline.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    // 4. Audit log workspace view
    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_guard',
      action: AUDIT_ACTIONS.INVESTIGATION_WORKSPACE_VIEWED,
      resource_type: 'incident',
      resource_id: incidentId,
      details: {
        timeline_events_count: timeline.length,
        notes_count: notes.length
      }
    });

    return {
      incident,
      timeline,
      notes,
      audit_history: audits,
      signals,
      iocs,
      correlations,
      group: groups[0] || null,
      attack_chain: attackChain
    };
  }
}

module.exports = new InvestigationWorkspaceService();
