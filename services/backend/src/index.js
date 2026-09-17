const express = require('express');
const http = require('http');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Route handlers
const authRoutes = require('./routes/authRoutes');
const checkRoutes = require('./routes/checkRoutes');
const telemetryRoutes = require('./routes/telemetryRoutes');
const incidentRoutes = require('./routes/incidentRoutes');
const guardianRoutes = require('./routes/guardianRoutes');
const analyticsRoutes = require('./routes/analyticsRoutes');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 5000;

// Standard Middlewares
app.use(cors());
app.use(express.json());

// Service Health Check
const healthHandler = (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'cyberguard-backend',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
};

app.get('/health', healthHandler);
app.get('/api/health', healthHandler);
app.get('/api/v1/health', healthHandler);

// API v1 Router
const v1Router = express.Router();
v1Router.use('/auth', authRoutes);
v1Router.use('/check', checkRoutes);
v1Router.use('/telemetry', telemetryRoutes);
v1Router.use('/incidents', incidentRoutes);
v1Router.use('/guardian', guardianRoutes);
v1Router.use('/analytics', analyticsRoutes);

// Mount versioned and root API routers
app.use('/api/v1', v1Router);
app.use('/api', v1Router);

// Centralized 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'NOT_FOUND',
    message: `Endpoint ${req.method} ${req.originalUrl} not found on CYBERGUARD Gateway`
  });
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error('[Gateway Unhandled Error]', err);
  res.status(err.status || 500).json({
    error: err.code || 'INTERNAL_SERVER_ERROR',
    message: err.message || 'An unexpected error occurred'
  });
});

// Start Server if not imported by tests
if (process.env.NODE_ENV !== 'test') {
  server.listen(PORT, () => {
    console.log(`[CYBERGUARD Gateway] Server listening on port ${PORT}`);
  });
}

module.exports = { app, server };
