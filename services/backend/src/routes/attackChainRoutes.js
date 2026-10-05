const express = require('express');
const attackChainController = require('../controllers/attackChainController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

const router = express.Router();

/**
 * Attack Chain & MITRE Progression Routes
 * Mounted on /incidents or versioned router
 */
router.get(
  '/:id/attack-chain',
  auth,
  roleCheck(['admin', 'analyst']),
  attackChainController.getAttackChain
);

router.get(
  '/:id/attack-chain/graph',
  auth,
  roleCheck(['admin', 'analyst']),
  attackChainController.getAttackChainGraph
);

module.exports = router;
