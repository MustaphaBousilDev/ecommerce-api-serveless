const express = require('express');
const serverless = require('serverless-http');
const authRoutes = require('./src/routers/authRouter');
const {v4: uuidv4} = require('uuid')


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

  console.log(`[${req.requestId}] 📥 ${req.method} ${req.path}`, {
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  })

  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - req.startTime;
    console.log(`[${req.requestId}] 📤 ${res.statusCode} ${req.method} ${req.path} - ${duration}ms`)
    if (duration > 2000) {
      console.warn(`[${req.requestId}] ⚠️ Slow request: ${duration}ms`)
    }
    originalSend.call(this, data)
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