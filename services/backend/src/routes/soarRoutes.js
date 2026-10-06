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

module.exports = router;
