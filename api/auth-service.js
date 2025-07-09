const express = require('express');
const serverless = require('serverless-http');
const authRoutes = require('./src/routers/authRouter');
const {v4: uuidv4} = require('uuid')
const { logRequest, logResponse, logPerformance } = require('./src/utils/logger');

// Environment validation 
const requiredEvns = ['USER_POOL_ID', 'USER_POOL_CLIENT_ID']
const missing = requiredEvns.filter(env => !process.env[env])
if(missing.length > 0) {
  console.error('❌ Missing required environment variables:', missing)
  process.exit(1)
}
console.log('✅ Environment validation passed');
console.log('🔧 Auth Service Configuration:');
console.log('- USER_POOL_ID:', process.env.USER_POOL_ID ? '✅ Set' : '❌ Missing');
console.log('- USER_POOL_CLIENT_ID:', process.env.USER_POOL_CLIENT_ID ? '✅ Set' : '❌ Missing');
console.log('- USER_POOL_CLIENT_SECRET:', process.env.USER_POOL_CLIENT_SECRET ? '✅ Set' : '⚠️ Optional');


const app = express();

//Security Headers Middleware 
app.use((req, res,next)=> {
  res.header('X-Content-Type-Options', 'nosniff')
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Requested-With');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');

  if(req.method === "OPTION"){
    return res.status(200).end()
  }
  next()
})

//request parsing with security limits 
app.use(express.json({ limit: '1mb',strict: true }))

//Request ID & Logging Middleware
app.use((req, res, next)=> {
  req.requestId = uuidv4();
  req.startTime = Date.now()

  logRequest(req.method, req.path, req.requestId, req.user?.userId, {
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    contentLength: req.get('content-length'),
    referer: req.get('referer')
  });

  // Enhanced response logging
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - req.startTime;
    
    // Log response
    logResponse(req.method, req.path, res.statusCode, req.requestId, req.user?.userId, {
      duration,
      contentLength: data ? data.length : 0
    });
    
    // Log performance if slow
    if (duration > 1000) {
      logPerformance('http_request', duration, req.requestId, req.user?.userId, {
        method: req.method,
        path: req.path,
        statusCode: res.statusCode
      });
    }
    
    originalSend.call(this, data);
  };
  next()
})

//Input validation middleware
app.use((req, res, next) => {
  if(req.body && typeof req.body === 'object'){
    const fieldCount = Object.keys(req.body).length
    if(fieldCount > 15){
      console.warn(`[${req.requestId}] 🚨 Too many fields: ${fieldCount}`)
      res.status(400).json({
        success: false, 
        error: 'To many fields in request', 
        requestId: req.requestId
      })
    }
    const bodyStr = JSON.stringify(req.body)
    if(bodyStr.length > 10000){
      console.warn(`[${req.requestId}] 🚨 Large payload: ${bodyStr.length} bytes`);
      return res.status(400).json({
        success: false,
        error: 'Request payload too large',
        requestId: req.requestId
      });
    }
  }
  next()
})

app.use(express.json());
app.use('/auth', authRoutes);
// Health check for this service
app.get('/health', (req, res) => {
  res.json({
    service: 'auth-service',
    status: 'healthy',
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
    environment: {
      region: process.env.AWS_REGION_NAME || 'us-east-1',
      userPoolConfigured: !!process.env.USER_POOL_ID,
      clientConfigured: !!process.env.USER_POOL_CLIENT_ID
    },
    version: '1.0.0'
  });
});
// Security info endpoint
app.get('/auth/info', (req, res) => {
  res.json({
    service: 'auth-service',
    endpoints: [
      'POST /auth/register', 'POST /auth/login', 'POST /auth/confirm',
      'POST /auth/logout', 'POST /auth/logout_all', 'POST /auth/resend_confirmation',
      'POST /auth/forgot_password', 'POST /auth/reset_password',
      'POST /auth/change_password', 'POST /auth/refresh_token'
    ],
    security: {
      headers: ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection'],
      validation: 'enabled',
      logging: 'enabled'
    },
    requestId: req.requestId
  });
});
// 404 Handler
app.use((req, res, next) => {
  console.warn(`[${req.requestId}] 🔍 404 Not Found: ${req.method} ${req.path}`);
  res.status(404).json({
    success: false,
    error: 'Not Found',
    service: 'auth-service',
    path: req.path,
    requestId: req.requestId
  });
});
// Global Error Handler (MUST BE LAST)
app.use((err, req, res, next) => {
  const requestId = req.requestId || 'unknown';
  console.error(`[${requestId}] 💥 Error:`, {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });
  
  res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    requestId,
    timestamp: new Date().toISOString()
  });
});
console.log('🚀 Auth Service Starting...');
console.log('📋 Security Features: ✅ Headers ✅ Validation ✅ Logging ✅ Error Handling');

module.exports.handler = serverless(app);