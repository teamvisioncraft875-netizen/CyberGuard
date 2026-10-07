const db = require('../config/db');
const { transaction } = require('../config/db');
const IncidentGroup = require('../models/IncidentGroup');
const IncidentGroupMember = require('../models/IncidentGroupMember');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

const SEVERITY_LEVELS = Object.freeze({
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
});

const GROUP_RULE_MAPPINGS = Object.freeze({
  shares_ioc: { group_type: 'campaign', confidence: 0.95 },
  same_attacker_ip: { group_type: 'distributed_attack', confidence: 0.85 },
  same_infrastructure: { group_type: 'campaign', confidence: 0.90 },
  same_user_campaign: { group_type: 'campaign', confidence: 0.80 },
  same_host_progression: { group_type: 'attack_chain', confidence: 0.90 }
});

function getHigherSeverity(s1, s2) {
  const v1 = SEVERITY_LEVELS[s1?.toLowerCase()] || 2;
  const v2 = SEVERITY_LEVELS[s2?.toLowerCase()] || 2;
  return v1 >= v2 ? (s1?.toLowerCase() || 'medium') : (s2?.toLowerCase() || 'medium');
}

/**
 * Computes aggregate metrics for an incident group.
 */
async function getGroupMetrics(groupId, client = null) {
  const dbClient = client || db;
  const text = `
    SELECT
      COUNT(i.id)::int AS incident_count,
      COUNT(CASE WHEN i.risk_level = 'high' THEN 1 END)::int AS high_risk_count,
      COUNT(CASE WHEN i.risk_level = 'critical' THEN 1 END)::int AS critical_count,
      ROUND(COALESCE(AVG(i.risk_score), 0))::int AS average_risk_score,
      COALESCE(MAX(i.created_at), MAX(g.created_at)) AS latest_activity
    FROM public.incident_groups g
    LEFT JOIN public.incident_group_members m ON m.group_id = g.id
    LEFT JOIN public.incidents i ON i.id = m.incident_id
    WHERE g.id = $1
    GROUP BY g.id;
  `;
  const res = await dbClient.query(text, [groupId]);
  if (!res.rows[0]) {
    return {
      incident_count: 0,
      high_risk_count: 0,
      critical_count: 0,
      average_risk_score: 0,
      latest_activity: new Date().toISOString()
    };
  }
  return res.rows[0];
}

/**
 * Automatically assigns or merges incidents into an incident group.
 */
async function assignGroup({
  sourceId,
  targetId,
  relationshipType,
  confidence = null,
  organizationId = null,
  client = null
}) {
  const executeAssignment = async (dbClient) => {
    // 1. Fetch incidents to verify details and tenant
    const incRes = await dbClient.query(
      `SELECT id, organization_id, threat_type, risk_level, risk_score, status
       FROM public.incidents
       WHERE id IN ($1, $2);`,
      [sourceId, targetId]
    );

    if (incRes.rows.length !== 2) {
      return null;
    }

    const sourceInc = incRes.rows.find(r => r.id === sourceId);
    const targetInc = incRes.rows.find(r => r.id === targetId);

    if (!sourceInc || !targetInc || sourceInc.organization_id !== targetInc.organization_id) {
      return null;
    }

    const orgId = organizationId || sourceInc.organization_id;

    // Determine group type and confidence based on rules G1-G5
    const ruleMapping = GROUP_RULE_MAPPINGS[relationshipType] || { group_type: 'campaign', confidence: 0.80 };
    const groupType = ruleMapping.group_type;
    const ruleConfidence = confidence != null ? confidence : ruleMapping.confidence;

    // 2. Check if either incident already belongs to an open/active group
    const [groupSource, groupTarget] = await Promise.all([
      IncidentGroupMember.findGroupByIncident(sourceId, dbClient),
      IncidentGroupMember.findGroupByIncident(targetId, dbClient)
    ]);

    // CASE 3: Both incidents already belong to the same group -> No-op
    if (groupSource && groupTarget && groupSource.id === groupTarget.id) {
      return groupSource;
    }

    // CASE 4: Both incidents belong to different active groups -> Merge groups
    if (groupSource && groupTarget && groupSource.id !== groupTarget.id) {
      // Determine which group survives:
      // Preserve: 1) higher severity, 2) higher confidence, 3) oldest created_at
      let survivor = groupSource;
      let orphan = groupTarget;

      const sevSource = SEVERITY_LEVELS[groupSource.severity?.toLowerCase()] || 2;
      const sevTarget = SEVERITY_LEVELS[groupTarget.severity?.toLowerCase()] || 2;

      if (sevTarget > sevSource) {
        survivor = groupTarget;
        orphan = groupSource;
      } else if (sevTarget === sevSource) {
        const confSource = parseFloat(groupSource.confidence_score) || 0;
        const confTarget = parseFloat(groupTarget.confidence_score) || 0;

        if (confTarget > confSource) {
          survivor = groupTarget;
          orphan = groupSource;
        } else if (confTarget === confSource) {
          const timeSource = new Date(groupSource.created_at).getTime();
          const timeTarget = new Date(groupTarget.created_at).getTime();
          if (timeTarget < timeSource) {
            survivor = groupTarget;
            orphan = groupSource;
          }
        }
      }

      // Move all memberships from orphan to survivor
      await IncidentGroupMember.moveMembers(orphan.id, survivor.id, dbClient);

      // Migrate attack chain snapshots from orphan to survivor group to preserve attack chains
      await dbClient.query(
        `UPDATE public.attack_chain_snapshots
         SET attack_chain_group_id = $1, updated_at = NOW()
         WHERE attack_chain_group_id = $2;`,
        [survivor.id, orphan.id]
      );

      // Delete orphan group
      await IncidentGroup.delete(orphan.id, dbClient);

      // Update survivor group updated_at and metadata
      await dbClient.query(
        `UPDATE public.incident_groups
         SET updated_at = NOW()
         WHERE id = $1;`,
        [survivor.id]
      );

      // Record audit log
      await auditLog({
        organization_id: orgId,
        actor_type: 'system_guard',
        action: AUDIT_ACTIONS.INCIDENT_GROUP_MERGED || 'INCIDENT_GROUP_MERGED',
        resource_type: 'incident_group',
        resource_id: survivor.id,
        details: {
          surviving_group_id: survivor.id,
          merged_group_id: orphan.id,
          reason: 'cross_incident_correlation_merge'
        }
      }, dbClient);

      try {
        const streamingService = require('./siem/streamingService');
        streamingService.publishCampaignUpdate({ group_id: survivor.id, merged_group_id: orphan.id, action: 'merge' }, orgId);
      } catch (sErr) {}

      return survivor;
    }

    // CASE 2: One incident belongs to a group, the other does not -> Attach second incident
    if (groupSource || groupTarget) {
      const existingGroup = groupSource || groupTarget;
      const incidentToAttach = groupSource ? targetInc : sourceInc;

      // Add to group
      await IncidentGroupMember.add({
        group_id: existingGroup.id,
        incident_id: incidentToAttach.id,
        added_by: 'rule_engine',
        confidence: ruleConfidence
      }, dbClient);

      // Upgrade severity if attached incident is higher
      const updatedSeverity = getHigherSeverity(existingGroup.severity, incidentToAttach.risk_level);
      if (updatedSeverity !== existingGroup.severity) {
        await dbClient.query(
          `UPDATE public.incident_groups
           SET severity = $1, updated_at = NOW()
           WHERE id = $2;`,
          [updatedSeverity, existingGroup.id]
        );
      } else {
        await dbClient.query(
          `UPDATE public.incident_groups
           SET updated_at = NOW()
           WHERE id = $1;`,
          [existingGroup.id]
        );
      }

      // Record audit log
      await auditLog({
        organization_id: orgId,
        actor_type: 'system_guard',
        action: AUDIT_ACTIONS.INCIDENT_GROUP_MEMBER_ADDED || 'INCIDENT_GROUP_MEMBER_ADDED',
        resource_type: 'incident_group',
        resource_id: existingGroup.id,
        details: {
          group_id: existingGroup.id,
          incident_id: incidentToAttach.id,
          relationship_type: relationshipType
        }
      }, dbClient);

      return existingGroup;
    }

    // CASE 1: Neither incident belongs to a group -> Create new group
    const initialSeverity = getHigherSeverity(sourceInc.risk_level, targetInc.risk_level);
    const titleType = groupType.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
    const groupTitle = `${titleType}: ${sourceInc.threat_type} & ${targetInc.threat_type}`;
    const groupDescription = `Automated cluster created via ${relationshipType} correlation`;

    const newGroup = await IncidentGroup.create({
      organization_id: orgId,
      title: groupTitle,
      description: groupDescription,
      group_type: groupType,
      status: 'open',
      severity: initialSeverity,
      confidence_score: ruleConfidence,
      primary_incident_id: sourceId,
      metadata: {
        created_via_rule: relationshipType,
        initial_incidents: [sourceId, targetId]
      }
    }, dbClient);

    // Add both incidents as members
    await IncidentGroupMember.add({
      group_id: newGroup.id,
      incident_id: sourceId,
      added_by: 'rule_engine',
      confidence: 1.000
    }, dbClient);

    await IncidentGroupMember.add({
      group_id: newGroup.id,
      incident_id: targetId,
      added_by: 'rule_engine',
      confidence: ruleConfidence
    }, dbClient);

    // Record audit logs
    await auditLog({
      organization_id: orgId,
      actor_type: 'system_guard',
      action: AUDIT_ACTIONS.INCIDENT_GROUP_CREATED || 'INCIDENT_GROUP_CREATED',
      resource_type: 'incident_group',
      resource_id: newGroup.id,
      details: {
        group_id: newGroup.id,
        group_type: groupType,
        primary_incident_id: sourceId
      }
    }, dbClient);

    await auditLog({
      organization_id: orgId,
      actor_type: 'system_guard',
      action: AUDIT_ACTIONS.INCIDENT_GROUP_MEMBER_ADDED || 'INCIDENT_GROUP_MEMBER_ADDED',
      resource_type: 'incident_group',
      resource_id: newGroup.id,
      details: {
        group_id: newGroup.id,
        incident_id: sourceId
      }
    }, dbClient);

    await auditLog({
      organization_id: orgId,
      actor_type: 'system_guard',
      action: AUDIT_ACTIONS.INCIDENT_GROUP_MEMBER_ADDED || 'INCIDENT_GROUP_MEMBER_ADDED',
      resource_type: 'incident_group',
      resource_id: newGroup.id,
      details: {
        group_id: newGroup.id,
        incident_id: targetId,
        relationship_type: relationshipType
      }
    }, dbClient);

    try {
      const streamingService = require('./siem/streamingService');
      streamingService.publishCampaignUpdate({ group_id: newGroup.id, group_type: groupType }, orgId);
    } catch (sErr) {}

    return newGroup;
  };

  if (client) {
    return executeAssignment(client);
  } else {
    return transaction(executeAssignment);
  }
}

/**
 * Resolves an incident group and all of its member incidents atomically.
 */
async function resolveGroup(groupId, organizationId, resolvedById = null, client = null) {
  const executeResolve = async (dbClient) => {
    // 1. Verify group exists and belongs to the organization
    const group = await IncidentGroup.findById(groupId, dbClient);
    if (!group) {
      const err = new Error('Incident group not found');
      err.status = 404;
      throw err;
    }

    if (organizationId && group.organization_id !== organizationId) {
      const err = new Error('Incident group not found');
      err.status = 404;
      throw err;
    }

    // 2. Mark group resolved
    const updatedGroup = await IncidentGroup.updateStatus(groupId, 'resolved', dbClient);

    // 3. Resolve all member incidents that are currently open/investigating
    const resolveIncRes = await dbClient.query(`
      UPDATE public.incidents
      SET status = 'resolved', resolved_at = NOW()
      WHERE id IN (
        SELECT incident_id FROM public.incident_group_members WHERE group_id = $1
      )
      AND status != 'resolved'
      RETURNING id;
    `, [groupId]);

    const resolvedIncidentIds = resolveIncRes.rows.map(r => r.id);

    // 4. Record audit log
    await auditLog({
      organization_id: group.organization_id,
      user_id: resolvedById,
      actor_type: 'admin',
      action: AUDIT_ACTIONS.INCIDENT_GROUP_RESOLVED || 'INCIDENT_GROUP_RESOLVED',
      resource_type: 'incident_group',
      resource_id: groupId,
      details: {
        group_id: groupId,
        resolved_by: resolvedById,
        resolved_incidents_count: resolvedIncidentIds.length,
        resolved_incident_ids: resolvedIncidentIds
      }
    }, dbClient);

    return {
      group: updatedGroup,
      resolved_incidents_count: resolvedIncidentIds.length,
      resolved_incident_ids: resolvedIncidentIds
    };
  };

  if (client) {
    return executeResolve(client);
  } else {
    return transaction(executeResolve);
  }
}

module.exports = {
  assignGroup,
  getGroupMetrics,
  resolveGroup,
  GROUP_RULE_MAPPINGS
};
