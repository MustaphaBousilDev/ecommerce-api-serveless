const express = require('express');
const serverless = require('serverless-http');
const authRoutes = require('./src/routers/authRouter');


const app = express();
app.use(express.json());
app.use('/auth', authRoutes);
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



module.exports.handler = serverless(app);