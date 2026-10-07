const db = require('../../config/db');

/**
 * Investigation Graph Engine — Models security investigations as interactive directed knowledge graphs
 * linking IOCs, Alerts, Incidents, Users, Assets, MITRE Techniques, Threat Intelligence, and Attack Chains.
 */
class InvestigationGraphService {
  /**
   * Constructs nodes and edges from provided entity sets.
   */
  buildGraphFromEntities({
    organization_id,
    target = null,
    alerts = [],
    incidents = [],
    iocs = [],
    users = [],
    assets = [],
    mitre = [],
    threatIntel = null,
    attackChains = []
  }) {
    const nodeMap = new Map();
    const edges = [];
    let edgeCounter = 1;

    const addNode = (id, type, label, extra = {}) => {
      if (!nodeMap.has(id)) {
        nodeMap.set(id, {
          id,
          type,
          label: String(label || id),
          organization_id,
          ...extra
        });
      }
    };

    const addEdge = (source, targetNode, relationship, label) => {
      if (source && targetNode && source !== targetNode) {
        const edgeId = `e-${edgeCounter++}`;
        edges.push({
          id: edgeId,
          source,
          target: targetNode,
          relationship,
          label: label || relationship
        });
      }
    };

    // 1. Target node if given
    let rootNodeId = null;
    if (target) {
      rootNodeId = `${target.type}-${target.id}`;
      addNode(rootNodeId, target.type, target.label || `${target.type} ${target.id}`, target.metadata || {});
    }

    // 2. Alerts
    alerts.forEach(al => {
      const alertNodeId = `alert-${al.id}`;
      addNode(alertNodeId, 'alert', al.title || `Alert ${al.id}`, {
        severity: al.severity,
        status: al.status,
        created_at: al.created_at
      });

      if (rootNodeId && rootNodeId !== alertNodeId) {
        addEdge(rootNodeId, alertNodeId, 'correlated_with', 'Correlated Alert');
      }

      if (al.incident_id) {
        const incNodeId = `incident-${al.incident_id}`;
        addNode(incNodeId, 'incident', `Incident ${al.incident_id}`);
        addEdge(alertNodeId, incNodeId, 'escalated_to', 'Escalated to Incident');
      }

      if (al.mitre_technique) {
        const mitreNodeId = `mitre-${al.mitre_technique.trim().toUpperCase()}`;
        addNode(mitreNodeId, 'mitre', al.mitre_technique.trim().toUpperCase(), { tactic: 'ATT&CK' });
        addEdge(alertNodeId, mitreNodeId, 'maps_to', 'Maps to MITRE');
      }
    });

    // 3. Incidents
    incidents.forEach(inc => {
      const incNodeId = `incident-${inc.id}`;
      addNode(incNodeId, 'incident', `Incident ${inc.threat_type || inc.id}`, {
        risk_level: inc.risk_level,
        risk_score: inc.risk_score,
        threat_type: inc.threat_type
      });

      if (rootNodeId && rootNodeId !== incNodeId) {
        addEdge(rootNodeId, incNodeId, 'linked_incident', 'Linked Incident');
      }

      if (inc.user_id) {
        const userNodeId = `user-${inc.user_id}`;
        addNode(userNodeId, 'user', `User ${inc.user_id}`);
        addEdge(incNodeId, userNodeId, 'compromised_user', 'Target User');
      }

      if (inc.device_id) {
        const assetNodeId = `asset-${inc.device_id}`;
        addNode(assetNodeId, 'asset', `Device ${inc.device_id}`);
        addEdge(incNodeId, assetNodeId, 'affected_asset', 'Impacted Asset');
      }
    });

    // 4. IOCs
    iocs.forEach(iocObj => {
      const iocVal = typeof iocObj === 'string' ? iocObj : iocObj.ioc_value || iocObj.value;
      const iocType = typeof iocObj === 'object' ? iocObj.ioc_type || 'indicator' : 'indicator';
      if (!iocVal) return;

      const iocNodeId = `ioc-${iocVal}`;
      addNode(iocNodeId, 'ioc', iocVal, {
        ioc_type: iocType,
        risk_score: iocObj.risk_score,
        threat_actor: iocObj.threat_actor
      });

      if (rootNodeId && rootNodeId !== iocNodeId) {
        addEdge(rootNodeId, iocNodeId, 'observed_ioc', 'Observed IOC');
      }

      if (iocObj.threat_actor) {
        const actorNodeId = `actor-${iocObj.threat_actor}`;
        addNode(actorNodeId, 'threat_intel', `Actor: ${iocObj.threat_actor}`);
        addEdge(iocNodeId, actorNodeId, 'attributed_to', 'Attributed Actor');
      }
    });

    // 5. Users
    users.forEach(u => {
      const uid = typeof u === 'string' ? u : (u.user_identifier || u.id);
      if (!uid) return;
      const uNodeId = `user-${uid}`;
      addNode(uNodeId, 'user', `User ${uid}`);
      if (rootNodeId && rootNodeId !== uNodeId) {
        addEdge(rootNodeId, uNodeId, 'affected_identity', 'Target Identity');
      }
    });

    // 6. Assets
    assets.forEach(a => {
      const aid = typeof a === 'string' ? a : (a.asset_identifier || a.id);
      if (!aid) return;
      const aNodeId = `asset-${aid}`;
      addNode(aNodeId, 'asset', `Asset ${aid}`);
      if (rootNodeId && rootNodeId !== aNodeId) {
        addEdge(rootNodeId, aNodeId, 'affected_asset', 'Impacted System');
      }
    });

    // 7. MITRE Techniques
    mitre.forEach(m => {
      const tech = typeof m === 'string' ? m : (m.technique || m.id);
      if (!tech) return;
      const mNodeId = `mitre-${tech.toUpperCase()}`;
      addNode(mNodeId, 'mitre', tech.toUpperCase());
      if (rootNodeId && rootNodeId !== mNodeId) {
        addEdge(rootNodeId, mNodeId, 'maps_to', 'Observed Technique');
      }
    });

    // 8. Attack Chains
    attackChains.forEach(ac => {
      const acNodeId = `chain-${ac.id}`;
      addNode(acNodeId, 'attack_chain', `Attack Chain (${ac.chain_length || 1} stages)`, {
        confidence_score: ac.confidence_score
      });
      if (ac.root_incident_id) {
        const rootIncNodeId = `incident-${ac.root_incident_id}`;
        if (nodeMap.has(rootIncNodeId)) {
          addEdge(rootIncNodeId, acNodeId, 'part_of_chain', 'Attack Chain Root');
        }
      }
    });

    return {
      nodes: Array.from(nodeMap.values()),
      edges
    };
  }

  /**
   * Generates a complete investigation graph for an entity within tenant boundary.
   */
  async generateGraph({ target_type, target_id, organization_id }, client = null) {
    if (!organization_id) throw new Error('InvestigationGraphService requires organization_id');
    const dbClient = client || db;

    const target = {
      type: target_type,
      id: target_id,
      label: `${target_type.toUpperCase()} ${target_id}`
    };

    let alerts = [];
    let incidents = [];
    let iocs = [];
    const users = [];
    const assets = [];
    const mitre = [];

    if (target_type === 'incident') {
      const incRes = await dbClient.query(
        `SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;`,
        [target_id, organization_id]
      );
      if (incRes.rows.length > 0) {
        const inc = incRes.rows[0];
        incidents.push(inc);
        if (inc.user_id) users.push(inc.user_id);
        if (inc.device_id) assets.push(inc.device_id);
        if (inc.fingerprint) iocs.push(inc.fingerprint);

        // Fetch sibling alerts
        const aRes = await dbClient.query(
          `SELECT * FROM public.siem_alerts WHERE incident_id = $1 AND organization_id = $2;`,
          [target_id, organization_id]
        );
        alerts = aRes.rows;
      }
    } else if (target_type === 'alert') {
      const alRes = await dbClient.query(
        `SELECT * FROM public.siem_alerts WHERE id = $1 AND organization_id = $2;`,
        [target_id, organization_id]
      );
      if (alRes.rows.length > 0) {
        const al = alRes.rows[0];
        alerts.push(al);
        if (al.mitre_technique) mitre.push(al.mitre_technique);
        const meta = al.metadata || {};
        if (meta.source_ip) iocs.push(meta.source_ip);
        if (meta.hostname) assets.push(meta.hostname);
        if (meta.username) users.push(meta.username);

        if (al.incident_id) {
          const incRes = await dbClient.query(
            `SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;`,
            [al.incident_id, organization_id]
          );
          if (incRes.rows.length > 0) incidents.push(incRes.rows[0]);
        }
      }
    } else if (target_type === 'ioc') {
      const iocRes = await dbClient.query(
        `SELECT * FROM public.threat_iocs WHERE ioc_value = $1 AND organization_id = $2;`,
        [target_id, organization_id]
      );
      if (iocRes.rows.length > 0) {
        iocs.push(iocRes.rows[0]);
      } else {
        iocs.push({ ioc_value: target_id, ioc_type: 'indicator' });
      }

      // Query alerts containing this IOC
      const aRes = await dbClient.query(
        `SELECT * FROM public.siem_alerts WHERE organization_id = $1 AND (metadata::text ILIKE $2 OR title ILIKE $2) LIMIT 10;`,
        [organization_id, `%${target_id}%`]
      );
      alerts = aRes.rows;
    }

    return this.buildGraphFromEntities({
      organization_id,
      target,
      alerts,
      incidents,
      iocs,
      users,
      assets,
      mitre
    });
  }
}

module.exports = new InvestigationGraphService();
