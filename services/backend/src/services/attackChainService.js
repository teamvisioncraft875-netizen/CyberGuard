const db = require('../config/db');
const { transaction } = require('../config/db');
const AttackChainSnapshot = require('../models/AttackChainSnapshot');
const IncidentGroup = require('../models/IncidentGroup');
const IncidentGroupMember = require('../models/IncidentGroupMember');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

const MITRE_PROGRESSION = Object.freeze(['TA0001', 'TA0002', 'TA0004', 'TA0011']);

const TECHNIQUE_TO_TACTIC = Object.freeze({
  // TA0001: Initial Access
  TA0001: 'TA0001',
  T1566: 'TA0001',
  'T1566.001': 'TA0001',
  'T1566.002': 'TA0001',
  T1190: 'TA0001',
  T1133: 'TA0001',
  T1586: 'TA0001',
  'T1586.002': 'TA0001',
  T1585: 'TA0001',

  // TA0002: Execution
  TA0002: 'TA0002',
  T1204: 'TA0002',
  'T1204.001': 'TA0002',
  'T1204.002': 'TA0002',
  T1059: 'TA0002',
  T1047: 'TA0002',
  T1053: 'TA0002',

  // TA0004: Privilege Escalation
  TA0004: 'TA0004',
  T1068: 'TA0004',
  T1548: 'TA0004',
  T1110: 'TA0004',
  T1552: 'TA0004',

  // TA0011: Command and Control
  TA0011: 'TA0011',
  T1071: 'TA0011',
  'T1071.001': 'TA0011',
  T1095: 'TA0011',
  T1571: 'TA0011',
  T1046: 'TA0011'
});

/**
 * Resolves MITRE tactic code (TA0001, TA0002, TA0004, TA0011) from technique id or name.
 */
function resolveTactic(techniqueId, techniqueName = '') {
  if (!techniqueId && !techniqueName) return null;

  const cleanId = String(techniqueId || '').trim().toUpperCase();
  if (TECHNIQUE_TO_TACTIC[cleanId]) return TECHNIQUE_TO_TACTIC[cleanId];

  if (/^TA\d{4}$/.test(cleanId)) return cleanId;

  const lowerName = String(techniqueName || '').toLowerCase();
  if (lowerName.includes('initial access')) return 'TA0001';
  if (lowerName.includes('user execution') || lowerName.includes('execution')) return 'TA0002';
  if (lowerName.includes('privilege escalation') || lowerName.includes('credential') || lowerName.includes('brute force')) return 'TA0004';
  if (lowerName.includes('command and control') || lowerName.includes('c2') || lowerName.includes('protocol anomaly')) return 'TA0011';

  return null;
}

/**
 * Checks if two tactics form an allowed progression step:
 * TA0001 -> TA0002 -> TA0004 -> TA0011
 */
function isDirectProgression(tacticA, tacticB) {
  if (!tacticA || !tacticB) return false;
  if (tacticA === 'TA0001' && tacticB === 'TA0002') return true;
  if (tacticA === 'TA0002' && tacticB === 'TA0004') return true;
  if (tacticA === 'TA0004' && tacticB === 'TA0011') return true;
  return false;
}

const attackChainService = {
  MITRE_PROGRESSION,
  TECHNIQUE_TO_TACTIC,
  resolveTactic,
  isDirectProgression,

  /**
   * Evaluates progression rules AC1 through AC4 between two incidents.
   * Returns matching rule result or null:
   * { matched: true, ruleId: 'AC1', fromId, toId, confidence: 0.85, fromTactic, toTactic }
   */
  evaluateProgression({
    incidentA,
    tacticsA = [],
    incidentB,
    tacticsB = []
  }) {
    if (!incidentA || !incidentB || incidentA.id === incidentB.id) return null;

    const timeA = new Date(incidentA.created_at).getTime();
    const timeB = new Date(incidentB.created_at).getTime();
    const timeDiffMs = Math.abs(timeA - timeB);
    const within12Hours = timeDiffMs <= 12 * 60 * 60 * 1000;

    if (!within12Hours) return null;

    // Determine chronological direction: earlier -> later
    const [earlier, later, earlierTactics, laterTactics] = timeA <= timeB
      ? [incidentA, incidentB, tacticsA, tacticsB]
      : [incidentB, incidentA, tacticsB, tacticsA];

    // Find progression step between earlier and later
    let progressionMatch = null;
    for (const tEarlier of earlierTactics) {
      for (const tLater of laterTactics) {
        if (isDirectProgression(tEarlier, tLater)) {
          progressionMatch = { from: tEarlier, to: tLater };
          break;
        }
      }
      if (progressionMatch) break;
    }

    if (!progressionMatch) return null;

    const { from, to } = progressionMatch;

    // RULE AC1: Same device, TA0001 -> TA0002
    if (
      earlier.device_id &&
      later.device_id &&
      earlier.device_id === later.device_id &&
      from === 'TA0001' &&
      to === 'TA0002'
    ) {
      return {
        matched: true,
        ruleId: 'AC1',
        fromId: earlier.id,
        toId: later.id,
        confidence: 0.85,
        fromTactic: from,
        toTactic: to
      };
    }

    // RULE AC2: Same device, TA0002 -> TA0004
    if (
      earlier.device_id &&
      later.device_id &&
      earlier.device_id === later.device_id &&
      from === 'TA0002' &&
      to === 'TA0004'
    ) {
      return {
        matched: true,
        ruleId: 'AC2',
        fromId: earlier.id,
        toId: later.id,
        confidence: 0.85,
        fromTactic: from,
        toTactic: to
      };
    }

    // RULE AC3: Same device, TA0004 -> TA0011
    if (
      earlier.device_id &&
      later.device_id &&
      earlier.device_id === later.device_id &&
      from === 'TA0004' &&
      to === 'TA0011'
    ) {
      return {
        matched: true,
        ruleId: 'AC3',
        fromId: earlier.id,
        toId: later.id,
        confidence: 0.85,
        fromTactic: from,
        toTactic: to
      };
    }

    // RULE AC4: Same user_id, different threat_type, matching progression
    if (
      earlier.user_id &&
      later.user_id &&
      earlier.user_id === later.user_id &&
      earlier.threat_type !== later.threat_type
    ) {
      return {
        matched: true,
        ruleId: 'AC4',
        fromId: earlier.id,
        toId: later.id,
        confidence: 0.80,
        fromTactic: from,
        toTactic: to
      };
    }

    return null;
  },

  /**
   * Traverses the correlation graph starting from incidentId up to maxDepth 2.
   * Traverses types: attack_chain_step, same_host_progression, same_user_campaign.
   * Prevents cycles and enforces tenant isolation.
   */
  async getAttackChain(incidentId, organizationId, client = null) {
    const dbClient = client || db;

    // Allowed edge types for attack chain progression
    const ALLOWED_TYPES = ['attack_chain_step', 'same_host_progression', 'same_user_campaign'];

    const visitedIncidents = new Set([incidentId]);
    const collectedEdges = [];
    let currentFrontier = [incidentId];
    const maxDepth = 2;

    for (let depth = 0; depth < maxDepth; depth++) {
      if (currentFrontier.length === 0) break;

      const edgeRes = await dbClient.query(
        `SELECT
           id,
           organization_id,
           source_incident_id,
           target_incident_id,
           relationship_type,
           confidence_score::float AS confidence_score,
           created_at
         FROM public.incident_relationships
         WHERE organization_id = $1
           AND (source_incident_id = ANY($2::uuid[]) OR target_incident_id = ANY($2::uuid[]))
           AND relationship_type = ANY($3::text[]);`,
        [organizationId, currentFrontier, ALLOWED_TYPES]
      );

      const nextFrontier = [];

      for (const edge of edgeRes.rows) {
        // Collect edge if not duplicate
        const edgeKey = `${edge.source_incident_id}-${edge.target_incident_id}-${edge.relationship_type}`;
        if (!collectedEdges.some(e => `${e.source_incident_id}-${e.target_incident_id}-${e.relationship_type}` === edgeKey)) {
          collectedEdges.push(edge);
        }

        const neighborId = currentFrontier.includes(edge.source_incident_id)
          ? edge.target_incident_id
          : edge.source_incident_id;

        if (!visitedIncidents.has(neighborId)) {
          visitedIncidents.add(neighborId);
          nextFrontier.push(neighborId);
        }
      }

      currentFrontier = nextFrontier;
    }

    // Load full details for all visited incidents under tenant isolation
    const allIds = Array.from(visitedIncidents);
    const incRes = await dbClient.query(
      `SELECT
         id,
         organization_id,
         threat_type,
         risk_score,
         risk_level,
         created_at,
         status,
         user_id,
         device_id
       FROM public.incidents
       WHERE id = ANY($1::uuid[])
         AND organization_id = $2;`,
      [allIds, organizationId]
    );

    const incidentsById = new Map();
    for (const inc of incRes.rows) {
      incidentsById.set(inc.id, inc);
    }

    // Fetch MITRE tactics for all visited incidents
    const mitreRes = await dbClient.query(
      `SELECT incident_id, technique_id, technique_name
       FROM public.mitre_mappings
       WHERE incident_id = ANY($1::uuid[]);`,
      [allIds]
    );

    const tacticsByInc = new Map();
    for (const m of mitreRes.rows) {
      const tac = resolveTactic(m.technique_id, m.technique_name);
      if (tac) {
        if (!tacticsByInc.has(m.incident_id)) {
          tacticsByInc.set(m.incident_id, new Set());
        }
        tacticsByInc.get(m.incident_id).add(tac);
      }
    }

    // Filter valid nodes that exist in DB
    const validIncidents = allIds
      .map(id => incidentsById.get(id))
      .filter(Boolean);

    // Sort chronologically
    validIncidents.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

    // Build timeline
    const timeline = validIncidents.map((inc, index) => {
      let relationshipType = null;
      if (index > 0) {
        // Find connecting edge between this incident and previous incidents in chain
        const prevIncident = validIncidents[index - 1];
        const connectingEdge = collectedEdges.find(e =>
          (e.source_incident_id === prevIncident.id && e.target_incident_id === inc.id) ||
          (e.source_incident_id === inc.id && e.target_incident_id === prevIncident.id)
        );

        relationshipType = connectingEdge ? connectingEdge.relationship_type : 'attack_chain_step';
      }

      const tacticsSet = tacticsByInc.get(inc.id) || new Set();

      return {
        incident_id: inc.id,
        threat_type: inc.threat_type,
        risk_score: typeof inc.risk_score === 'number' ? inc.risk_score : Number(inc.risk_score || 0),
        created_at: inc.created_at,
        mitre_tactics: Array.from(tacticsSet),
        relationship: relationshipType
      };
    });

    // Compute chain confidence: average of all edge confidence scores
    let confidenceScore = 0.800;
    if (collectedEdges.length > 0) {
      const totalConf = collectedEdges.reduce((acc, e) => acc + (parseFloat(e.confidence_score) || 0.80), 0);
      confidenceScore = parseFloat((totalConf / collectedEdges.length).toFixed(3));
    }

    const rootIncident = incidentsById.get(incidentId) || validIncidents[0] || null;

    return {
      root_incident: rootIncident,
      chain_length: timeline.length,
      confidence_score: confidenceScore,
      timeline,
      nodes: validIncidents.map(inc => ({
        id: inc.id,
        label: inc.threat_type,
        threat_type: inc.threat_type,
        risk_score: inc.risk_score,
        created_at: inc.created_at
      })),
      edges: collectedEdges.map(edge => ({
        source: edge.source_incident_id,
        target: edge.target_incident_id,
        type: edge.relationship_type,
        confidence: edge.confidence_score
      }))
    };
  },

  /**
   * Generates or updates an attack chain snapshot.
   * If chain_length >= 3, automatically clusters incidents into group_type='attack_chain'.
   */
  async generateSnapshot(incidentId, organizationId, client = null) {
    const executeSnapshot = async (dbClient) => {
      const chainData = await this.getAttackChain(incidentId, organizationId, dbClient);
      const { chain_length, confidence_score, timeline } = chainData;

      let attackChainGroupId = null;

      // Group Integration: If chain_length >= 3, automatically create/update attack_chain group
      if (chain_length >= 3) {
        const timelineIds = timeline.map(t => t.incident_id);

        // Check if any incident in timeline already belongs to an attack_chain group
        const existingGroupRes = await dbClient.query(`
          SELECT g.id
          FROM public.incident_groups g
          JOIN public.incident_group_members m ON m.group_id = g.id
          WHERE g.organization_id = $1
            AND g.group_type = 'attack_chain'
            AND g.status != 'resolved'
            AND m.incident_id = ANY($2::uuid[])
          LIMIT 1;
        `, [organizationId, timelineIds]);

        if (existingGroupRes.rows.length > 0) {
          attackChainGroupId = existingGroupRes.rows[0].id;
          // Add all timeline incidents to this existing group
          for (const incId of timelineIds) {
            await IncidentGroupMember.add({
              group_id: attackChainGroupId,
              incident_id: incId,
              added_by: 'rule_engine',
              confidence: confidence_score
            }, dbClient);
          }
        } else {
          // Create new attack_chain group
          const threatChainTitle = timeline.map(t => t.threat_type).join(' -> ');
          const newGroup = await IncidentGroup.create({
            organization_id: organizationId,
            title: `Attack Chain: ${threatChainTitle}`,
            description: `Automated multi-stage MITRE ATT&CK progression chain (${chain_length} stages)`,
            group_type: 'attack_chain',
            status: 'open',
            severity: 'critical',
            confidence_score: confidence_score,
            primary_incident_id: incidentId,
            metadata: {
              chain_length,
              stages: timeline.map(t => t.mitre_tactics)
            }
          }, dbClient);

          attackChainGroupId = newGroup.id;

          for (const incId of timelineIds) {
            await IncidentGroupMember.add({
              group_id: attackChainGroupId,
              incident_id: incId,
              added_by: 'rule_engine',
              confidence: confidence_score
            }, dbClient);
          }

          await auditLog({
            organization_id: organizationId,
            actor_type: 'system_guard',
            action: AUDIT_ACTIONS.INCIDENT_GROUP_CREATED || 'INCIDENT_GROUP_CREATED',
            resource_type: 'incident_group',
            resource_id: attackChainGroupId,
            details: {
              group_id: attackChainGroupId,
              group_type: 'attack_chain',
              chain_length
            }
          }, dbClient);
        }
      }

      // Check if snapshot already exists for this root incident
      const existingSnapshot = await AttackChainSnapshot.findByIncident(incidentId, dbClient);

      let snapshot;
      if (existingSnapshot) {
        snapshot = await AttackChainSnapshot.update(existingSnapshot.id, {
          attack_chain_group_id: attackChainGroupId || existingSnapshot.attack_chain_group_id,
          confidence_score,
          chain_length,
          timeline,
          metadata: {
            updated_via: 'attack_chain_progression'
          }
        }, dbClient);

        await auditLog({
          organization_id: organizationId,
          actor_type: 'system_guard',
          action: AUDIT_ACTIONS.ATTACK_CHAIN_UPDATED || 'ATTACK_CHAIN_UPDATED',
          resource_type: 'attack_chain_snapshot',
          resource_id: snapshot.id,
          details: {
            root_incident_id: incidentId,
            chain_length,
            confidence_score
          }
        }, dbClient);
      } else {
        snapshot = await AttackChainSnapshot.create({
          organization_id: organizationId,
          root_incident_id: incidentId,
          attack_chain_group_id: attackChainGroupId,
          confidence_score,
          chain_length,
          timeline,
          metadata: {
            created_via: 'attack_chain_progression'
          }
        }, dbClient);

        await auditLog({
          organization_id: organizationId,
          actor_type: 'system_guard',
          action: AUDIT_ACTIONS.ATTACK_CHAIN_CREATED || 'ATTACK_CHAIN_CREATED',
          resource_type: 'attack_chain_snapshot',
          resource_id: snapshot.id,
          details: {
            root_incident_id: incidentId,
            chain_length,
            confidence_score
          }
        }, dbClient);
      }

      return snapshot;
    };

    if (client) {
      return executeSnapshot(client);
    } else {
      return transaction(executeSnapshot);
    }
  },

  /**
   * Returns React Flow / Cytoscape formatted graph representation.
   */
  async getAttackChainGraph(incidentId, organizationId, client = null) {
    const chainData = await this.getAttackChain(incidentId, organizationId, client);
    return {
      nodes: chainData.nodes.map(n => ({
        id: n.id,
        label: n.label || n.threat_type
      })),
      edges: chainData.edges.map(e => ({
        source: e.source,
        target: e.target,
        type: e.type
      }))
    };
  }
};

module.exports = attackChainService;
