const express = require('express');
const router = express.Router();
const soarController = require('../controllers/soarController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// All SOAR endpoints require authentication and SOC Analyst / Senior Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst', 'senior_analyst']));

// 1. Playbook Management
router.post('/playbooks', soarController.createPlaybook);
router.get('/playbooks', soarController.listPlaybooks);
router.get('/playbooks/:id', soarController.getPlaybookById);
router.patch('/playbooks/:id', soarController.updatePlaybook);
router.delete('/playbooks/:id', roleCheck(['admin']), soarController.deletePlaybook);
router.post('/playbooks/:id/execute', soarController.executePlaybookManually);

// 2. Case Management (Sprint B Phase 2)
router.post('/cases', soarController.createCase);
router.post('/cases/from-alert/:alert_id', soarController.createCaseFromAlert);
router.get('/cases', soarController.listCases);
router.get('/cases/:id', soarController.getCaseById);
router.patch('/cases/:id', soarController.updateCase);
router.patch('/cases/:id/status', soarController.updateCaseStatus);
router.post('/cases/:id/incidents', soarController.attachIncidents);
router.post('/cases/:id/iocs', soarController.attachIOCs);
router.post('/cases/:id/evidence', soarController.addCaseEvidence);
router.get('/cases/:id/evidence', soarController.listCaseEvidence);
router.delete('/cases/:id', roleCheck(['admin']), soarController.deleteCase);

// 3. Executions & Resiliency Recovery
router.get('/executions', soarController.listExecutions);
router.get('/executions/:id', soarController.getExecutionById);
router.post('/executions/recover', roleCheck(['admin']), soarController.recoverExecutions);

// 4. Approvals & Escalation Chains
router.get('/approvals', soarController.listApprovals);
router.post('/approvals/:id/approve', soarController.approveExecution);
router.post('/approvals/:id/reject', soarController.rejectExecution);
router.post('/approvals/:id/escalate', soarController.escalateApproval);

// 5. Playbook Analytics & Metrics
router.get('/metrics', soarController.getMetrics);
router.get('/metrics/playbooks/:id', soarController.getPlaybookMetrics);

// 6. Connectors & Enterprise Orchestration (Sprint B Phase 3)
router.post('/connectors', roleCheck(['admin', 'senior_analyst']), soarController.createConnector);
router.get('/connectors', soarController.listConnectors);
router.get('/connectors/:id', soarController.getConnectorById);
router.patch('/connectors/:id', roleCheck(['admin', 'senior_analyst']), soarController.updateConnector);
router.patch('/connectors/:id/status', roleCheck(['admin', 'senior_analyst']), soarController.updateConnectorStatus);
router.post('/connectors/:id/test', soarController.testConnector);
router.get('/connectors/:id/logs', soarController.getConnectorLogs);
router.delete('/connectors/:id', roleCheck(['admin']), soarController.deleteConnector);

// 7. IOC Response Automation (Sprint B Phase 4)
router.post('/ioc/automate', soarController.automateIocResponse);

// 8. Threat Intel Enrichment Pipeline
router.post('/enrich/alert/:id', soarController.enrichAlert);
router.post('/enrich/case/:id', soarController.enrichCase);

// 9. Automated Response Recommendations
router.post('/recommendations/generate', soarController.generateRecommendations);
router.get('/recommendations', soarController.listRecommendations);
router.post('/recommendations/:id/apply', soarController.applyRecommendation);
router.post('/recommendations/:id/dismiss', soarController.dismissRecommendation);

// 10. Playbook Effectiveness Analytics
router.get('/analytics/effectiveness', soarController.getEffectivenessAnalytics);
router.get('/analytics/playbooks/:id', soarController.getPlaybookEffectiveness);
router.get('/analytics/actions', soarController.getActionEffectiveness);

// 11. Response Knowledge Base
router.post('/knowledge-base', roleCheck(['admin', 'senior_analyst']), soarController.createKnowledgeBaseArticle);
router.get('/knowledge-base', soarController.listKnowledgeBaseArticles);
router.get('/knowledge-base/:id', soarController.getKnowledgeBaseArticleById);
router.patch('/knowledge-base/:id', roleCheck(['admin', 'senior_analyst']), soarController.updateKnowledgeBaseArticle);
router.delete('/knowledge-base/:id', roleCheck(['admin']), soarController.deleteKnowledgeBaseArticle);
router.post('/knowledge-base/:id/link-case', soarController.linkKnowledgeBaseCase);
router.post('/knowledge-base/:id/link-playbook', soarController.linkKnowledgeBasePlaybook);

// 12. SOAR Dashboards
router.get('/dashboard/executive', soarController.getExecutiveDashboard);
router.get('/dashboard/analyst', soarController.getAnalystDashboard);
router.get('/dashboard/engineering', soarController.getEngineeringDashboard);

module.exports = router;

