const { CognitoJwtVerifier } = require("aws-jwt-verify");
const { USER_POOL_ID, USER_POOL_CLIENT_ID } = require('../config/aws');
const { addSubsegment, closeSubsegment } = require('../utils/xray');
const { logAuth, logSecurity, logError, logPerformance } = require('../utils/logger');

// Cognito JWT Verifier Setup
const verifier = CognitoJwtVerifier.create({
  userPoolId: USER_POOL_ID,
  tokenUse: "access",
  clientId: USER_POOL_CLIENT_ID,
});

const authenticateToken = async (req, res, next) => {
  const subsegment = addSubsegment('jwt-authentication');
  
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  const requestId = req.requestId;

  if (!token) {
    logSecurity('missing_token', null, requestId, { 
      path: req.path, 
      ip: req.ip 
    });
    
    if (subsegment) {
      subsegment.addAnnotation('auth_result', 'missing_token');
      closeSubsegment(subsegment);
    }
    
    return res.status(401).json({ 
      success: false,
      error: 'Access token required',
      requestId
    });
  }

  try {
    const startTime = Date.now();
    
    // Verify the JWT token
    const payload = await verifier.verify(token);
    const authDuration = Date.now() - startTime;
    
    // Add X-Ray annotations if available
    if (subsegment) {
      subsegment.addAnnotation('auth_result', 'success');
      subsegment.addAnnotation('user_id', payload.sub);
      subsegment.addMetadata('auth', {
        email: payload.email,
        duration: authDuration
      });
    }
    
    // Log successful authentication
    logAuth('token_verified', payload.sub, payload.email, requestId, true);
    
    // Log performance if slow
    if (authDuration > 200) {
      logPerformance('jwt_verification', authDuration, requestId, payload.sub);
    }
    
    // Add user info to request
    req.user = {
      userId: payload.sub,
      email: payload.email,
      username: payload.username,
      name: payload.name || payload.given_name || 'Unknown'
    };

    closeSubsegment(subsegment);
    next();
    
  } catch (error) {
    // Add error to X-Ray if available
    if (subsegment) {
      subsegment.addAnnotation('auth_result', 'failed');
      try {
        subsegment.addError(error);
      } catch (e) {
        // Ignore X-Ray errors
      }
    }
    
    // Log authentication failure
    logAuth('token_verification_failed', null, null, requestId, false, error);
    logSecurity('invalid_token', null, requestId, { 
      error: error.message,
      path: req.path 
    });
    
    closeSubsegment(subsegment);
    
    return res.status(403).json({ 
      success: false,
      error: 'Invalid or expired token',
      requestId
    });
  }
};

module.exports = {
  authenticateToken
};