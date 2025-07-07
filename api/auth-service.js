const express = require('express');
const serverless = require('serverless-http');
const authRoutes = require('./src/routes/authRoutes');
const { requestLogger, errorLogger } = require('./src/middlewares/logger');
const { logger } = require('./src/utils/logger');

// Express App Setup
const app = express();

// Middleware
app.use(express.json());
app.use(requestLogger);

app.use('/auth', authRoutes);

app.use(errorLogger);

// Health check for this service
app.get('/health', (req, res) => {
  res.json({
    service: 'auth-service',
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    service: 'auth-service',
    path: req.path
  });
});

logger.info('Auth Service Starting', {
  service: 'auth-service',
  endpoints: ['/auth/register', '/auth/login', '/auth/confirm', '/auth/resend-confirmation', '/auth/forgot-password', '/auth/reset-password']
});

module.exports.handler = serverless(app);