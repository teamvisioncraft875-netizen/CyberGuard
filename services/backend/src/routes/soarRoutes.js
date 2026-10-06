const express = require('express');
const router = express.Router();
const soarController = require('../controllers/soarController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// All SOAR endpoints require authentication and SOC Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst']));

// 1. Playbook Management
router.post('/playbooks', soarController.createPlaybook);
router.get('/playbooks', soarController.listPlaybooks);
router.get('/playbooks/:id', soarController.getPlaybookById);
router.patch('/playbooks/:id', soarController.updatePlaybook);
router.delete('/playbooks/:id', soarController.deletePlaybook);
router.post('/playbooks/:id/execute', soarController.executePlaybookManually);

// 2. Executions
router.get('/executions', soarController.listExecutions);
router.get('/executions/:id', soarController.getExecutionById);

// 3. Approvals (Only Admin may approve/reject actions)
router.get('/approvals', soarController.listApprovals);
router.post('/approvals/:id/approve', roleCheck(['admin']), soarController.approveExecution);
router.post('/approvals/:id/reject', roleCheck(['admin']), soarController.rejectExecution);

module.exports = router;
