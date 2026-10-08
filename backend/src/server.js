const express = require('express');
const cors = require('cors');
require('dotenv').config();

const apiRoutes = require('./routes/api');
const supabaseService = require('./services/supabaseService');

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for all incoming requests (supports any frontend port, e.g. 3000, 5173, etc.)
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${duration}ms)`);
  });
  next();
});

// Root landing endpoint
app.get('/', (req, res) => {
  res.json({
    project: 'PhishGuard - Phishing URL Detector API',
    status: 'Running',
    database: supabaseService.getStatus(),
    endpoints: {
      scanUrl: {
        method: 'POST',
        path: '/api/scan',
        exampleBody: { url: 'http://fake-bank.com/login' }
      },
      getScans: {
        method: 'GET',
        path: '/api/scans'
      },
      getHistoryAlias: {
        method: 'GET',
        path: '/api/history'
      },
      healthCheck: {
        method: 'GET',
        path: '/api/health'
      }
    },
    documentation: 'https://github.com/iamsaintzeno/PhishGuard.git'
  });
});

// Mount API routes under /api and also directly under / for flexible access
app.use('/api', apiRoutes);
app.use('/', apiRoutes);

// 404 handler for unknown routes
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    requestedUrl: req.originalUrl,
    availableEndpoints: ['POST /api/scan', 'GET /api/scans', 'GET /api/history', 'GET /api/health']
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('💥 Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// Start Express server
const server = app.listen(PORT, () => {
  console.log('====================================================');
  console.log(`🛡️  PhishGuard Backend API Server running successfully!`);
  console.log(`📡 Local Server URL:  http://localhost:${PORT}`);
  console.log(`🔍 Scan Endpoint:     http://localhost:${PORT}/api/scan (POST)`);
  console.log(`📜 History Endpoint:  http://localhost:${PORT}/api/scans (GET)`);
  console.log(`❤️  Health Endpoint:   http://localhost:${PORT}/api/health (GET)`);
  console.log('====================================================');
});

module.exports = { app, server };
