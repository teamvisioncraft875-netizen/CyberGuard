const express = require('express');
const http = require('http');
const cors = require('cors');

// Load centralized configuration & validate secrets at startup (throws if JWT_SECRET missing)
const config = require('./config');

// Route handlers
const authRoutes = require('./routes/authRoutes');
const checkRoutes = require('./routes/checkRoutes');
const telemetryRoutes = require('./routes/telemetryRoutes');
const incidentRoutes = require('./routes/incidentRoutes');
const guardianRoutes = require('./routes/guardianRoutes');
const analyticsRoutes = require('./routes/analyticsRoutes');
const actionRoutes = require('./routes/actionRoutes');
const userRoutes = require('./routes/userRoutes');
const mediaRoutes = require('./routes/mediaRoutes');

const { checkLimiter, generalLimiter, searchLimiter } = require('./middlewares/rateLimiter');

const { initSocket } = require('./config/socket');

const app = express();
const server = http.createServer(app);
const io = initSocket(server);

const PORT = config.PORT || process.env.PORT || 5000;

// Standard Middlewares (support multimedia Base64 payloads up to 15 MB)
app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));

// Service Health & Readiness Checks (unthrottled monitoring endpoints)
const healthHandler = (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'cyberguard-backend',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
};

app.get('/health', healthHandler);
app.get('/health/readiness', healthHandler);
app.get('/api/health', healthHandler);
app.get('/api/health/readiness', healthHandler);
app.get('/api/v1/health', healthHandler);
app.get('/api/v1/health/readiness', healthHandler);

// API v1 Router
const v1Router = express.Router();
v1Router.use('/auth', authRoutes);
v1Router.use('/check', checkLimiter, checkRoutes);
v1Router.use('/telemetry', generalLimiter, telemetryRoutes);
v1Router.use('/incidents', generalLimiter, incidentRoutes);
v1Router.use('/guardian', generalLimiter, guardianRoutes);
v1Router.use('/analytics', generalLimiter, analyticsRoutes);
v1Router.use('/actions', generalLimiter, actionRoutes);
v1Router.use('/users', searchLimiter, userRoutes);
v1Router.use('/media', generalLimiter, mediaRoutes);

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

module.exports = { app, server, io };
