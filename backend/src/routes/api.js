const express = require('express');
const router = express.Router();
const { scanUrl, getScans, getHealth } = require('../controllers/scanController');

// Scan URL endpoint
router.post('/scan', scanUrl);

// Scan history endpoints (both /scans and /history supported)
router.get('/scans', getScans);
router.get('/history', getScans);

// Health check endpoint
router.get('/health', getHealth);

module.exports = router;
