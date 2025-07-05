const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} = require("@aws-sdk/lib-dynamodb");
const { SignUpCommand, CognitoIdentityProviderClient } = require("@aws-sdk/client-cognito-identity-provider");

const express = require("express");
const serverless = require("serverless-http");
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const { v4: uuidv4 } = require('uuid');

// Import your existing Winston logger
const { 
  logger, 
  logRequest, 
  logResponse, 
  logAuth, 
  logDatabase, 
  logBusiness, 
  logError, 
  logPerformance, 
  logSecurity 
} = require('./utils/logger');
const { requestLoggin } = require("./middlewares/logger");

// X-Ray Configuration with error handling
let AWSXRay;
let isXRayAvailable = false;

try {
  AWSXRay = require('aws-xray-sdk-core');
  // Check if running in AWS environment
  if (process.env.AWS_EXECUTION_ENV || process.env._X_AMZN_TRACE_ID) {
    AWSXRay.config([AWSXRay.plugins.ECSPlugin, AWSXRay.plugins.EC2Plugin]);
    isXRayAvailable = true;
    logger.info('X-Ray tracing enabled');
  } else {
    logger.info('X-Ray tracing disabled - local development');
  }
} catch (error) {
  logger.warn('X-Ray SDK not available, tracing disabled', { error: error.message });
  isXRayAvailable = false;
}

// Environment Variables
const USERS_TABLE = process.env.USERS_TABLE;
const USER_POOL_ID = process.env.USER_POOL_ID;
const USER_POOL_CLIENT_ID = process.env.USER_POOL_CLIENT_ID;
const AWS_REGION = process.env.AWS_REGION_NAME;

// AWS SDK v3 Clients with conditional X-Ray tracing
let client, cognitoClient;

if (isXRayAvailable) {
  client = AWSXRay.captureAWSv3Client(new DynamoDBClient({
    region: AWS_REGION
  }));
  cognitoClient = AWSXRay.captureAWSv3Client(new CognitoIdentityProviderClient({
    region: AWS_REGION,
  }));
} else {
  client = new DynamoDBClient({
    region: AWS_REGION
  });
  cognitoClient = new CognitoIdentityProviderClient({
    region: AWS_REGION,
  });
}

const docClient = DynamoDBDocumentClient.from(client);

// Cognito JWT Verifier Setup
const verifier = CognitoJwtVerifier.create({
  userPoolId: USER_POOL_ID,
  tokenUse: "access",
  clientId: USER_POOL_CLIENT_ID,
});

// X-Ray Helper Functions
const getSegment = () => {
  try {
    return isXRayAvailable ? AWSXRay.getSegment() : null;
  } catch (error) {
    return null;
  }
};

const addSubsegment = (name) => {
  try {
    const segment = getSegment();
    return segment ? segment.addNewSubsegment(name) : null;
  } catch (error) {
    return null;
  }
};

const closeSubsegment = (subsegment) => {
  try {
    if (subsegment) subsegment.close();
  } catch (error) {
    // Ignore errors when closing subsegments
  }
};

// Your Custom Request Logging Middleware with X-Ray Integration

// Your Custom Error Logging Middleware
const errorLoggin = (err, req, res, next) => {
  const requestId = req.requestId || 'unknown';
  
  logError(err, requestId, req.user?.userId, {
    method: req.method,
    path: req.path,
    body: req.body
  });
  
  // Add error to X-Ray if available
  const segment = getSegment();
  if (segment) {
    try {
      segment.addError(err);
    } catch (e) {
      // Ignore X-Ray errors
    }
  }
  
  res.status(500).json({
    error: 'Internal Server Error',
    requestId,
    timestamp: new Date().toISOString()
  });
};

// X-Ray Express Middleware (conditional)
const xrayMiddleware = (req, res, next) => {
  if (isXRayAvailable && AWSXRay.express) {
    return AWSXRay.express.openSegment('ecommerce-api')(req, res, next);
  } else {
    // Pass through if X-Ray not available
    next();
  }
};

const xrayCloseMiddleware = (req, res, next) => {
  if (isXRayAvailable && AWSXRay.express) {
    return AWSXRay.express.closeSegment()(req, res, next);
  } else {
    // Pass through if X-Ray not available
    next();
  }
};

// JWT Authentication Middleware with conditional X-Ray tracing
const authenticateToken = async (req, res, next) => {
  const subsegment = addSubsegment('jwt-authentication');
  
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  const requestId = req.requestId;

  if (!token) {
    logSecurity('missing_token', null, requestId, { path: req.path, ip: req.ip });
    
    if (subsegment) {
      subsegment.addAnnotation('auth_result', 'missing_token');
      closeSubsegment(subsegment);
    }
    return res.status(401).json({ error: 'Access token required' });
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
    
    // Log successful authentication using your Winston logger
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
    
    // Log authentication failure using your Winston logger
    logAuth('token_verification_failed', null, null, requestId, false, error);
    logSecurity('invalid_token', null, requestId, { 
      error: error.message,
      path: req.path 
    });
    
    closeSubsegment(subsegment);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Express App Setup
const app = express();

// Apply middleware in correct order
app.use(xrayMiddleware);          // X-Ray must be first
app.use(express.json());          
app.use(requestLoggin);           // Your custom request logging middleware

// Log application startup
logger.info('E-commerce API Starting', {
  environment: process.env.NODE_ENV || 'development',
  userPoolId: USER_POOL_ID ? 'configured' : 'missing',
  clientId: USER_POOL_CLIENT_ID ? 'configured' : 'missing',
  region: AWS_REGION,
  xrayEnabled: isXRayAvailable
});

// Health Check Route (Public)
app.get("/", (req, res) => {
  const segment = getSegment();
  if (segment) {
    segment.addAnnotation('endpoint', 'health_check');
  }
  
  res.json({ 
    message: "E-commerce API is running",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
    requestId: req.requestId,
    tracing: isXRayAvailable ? 'enabled' : 'disabled',
    public: [
        "GET /",
        "GET /health", 
        "POST /auth/register",
        "POST /auth/confirm", 
        "POST /auth/login",
        "POST /auth/forgot-password",
        "POST /auth/reset-password"
      ],
    protected: [
        "GET /auth/status", 
        "GET /profile", 
        "POST /users",
        "GET /users/:userId", 
        "GET /protected"
      ]
  });
});

// Health Check Route (Public)
app.get("/health", (req, res) => {
  const segment = getSegment();
  if (segment) {
    segment.addAnnotation('endpoint', 'health_detailed');
  }
  
  const healthStatus = {
    status: "healthy",
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
    tracing: isXRayAvailable ? 'enabled' : 'disabled',
    environment: {
      userPoolId: USER_POOL_ID ? "configured" : "missing",
      clientId: USER_POOL_CLIENT_ID ? "configured" : "missing",
      region: AWS_REGION,
      usersTable: USERS_TABLE
    }
  };
  
  if (segment) {
    segment.addMetadata('health', healthStatus);
  }
  res.json(healthStatus);
});

// Registration Route with conditional X-Ray tracing and Winston logging
app.post("/auth/register", async (req, res) => {
  const subsegment = addSubsegment('user-registration');
  
  const {email, password, name, phone, address} = req.body;
  const requestId = req.requestId;
  
  // Log registration attempt
  logBusiness('registration_attempt', null, requestId, { email });
  
  try {
    // Validation
    if (!email || !password || !name) {
      logSecurity('registration_invalid_input', null, requestId, { 
        missing: { email: !email, password: !password, name: !name }
      });
      if (subsegment) {
        subsegment.addAnnotation('result', 'validation_failed');
      }
      closeSubsegment(subsegment);
      return res.status(400).json({
        error: 'Email, password and name are required'
      });
    }
    
    if (password.length < 8) {
      logSecurity('weak_password_attempt', null, requestId, { email });
      if (subsegment) {
        subsegment.addAnnotation('result', 'weak_password');
      }
      closeSubsegment(subsegment);
      return res.status(400).json({
        error: 'Password must be at least 8 characters long'
      });
    }
    
    const startTime = Date.now();
    
    const params = {
      ClientId: USER_POOL_CLIENT_ID,
      Username: email, 
      Password: password,
      UserAttributes: [
        {
          Name: 'email',
          Value: email,
        },
        {
          Name: "name",
          Value: name
        },
        {
          Name: "given_name",
          Value: name.split(' ')[0]
        },
        {
          Name: "family_name",
          Value: name.split(' ').slice(1).join(' ') || name.split(' ')[0]
        },
        {
          Name: "address",
          Value: address || "Not provided"
        }
      ]
    };
    
    if(phone) {
      params.UserAttributes.push({
        Name: "phone_number",
        Value: phone
      });
    }
    
    const command = new SignUpCommand(params);
    const result = await cognitoClient.send(command);
    
    const duration = Date.now() - startTime;
    
    // Add X-Ray annotations if available
    if (subsegment) {
      subsegment.addAnnotation('result', 'success');
      subsegment.addAnnotation('user_id', result.UserSub);
      subsegment.addMetadata('registration', {
        email,
        confirmationRequired: !result.UserConfirmed,
        duration
      });
    }
    
    // Log successful registration using Winston logger
    logAuth('user_registered', result.UserSub, email, requestId, true);
    logBusiness('registration_success', result.UserSub, requestId, {
      email,
      confirmationRequired: !result.UserConfirmed
    });
    logPerformance('cognito_signup', duration, requestId);
    
    closeSubsegment(subsegment);
    
    res.status(201).json({
      message: "User registered successfully",
      userId: result.UserSub,
      email: email,
      confirmationRequired: !result.UserConfirmed,
      nextStep: result.UserConfirmed ? "login": "confirm_email",
      requestId
    });
    
  } catch(error) {
    // Add error to X-Ray if available
    if (subsegment) {
      subsegment.addAnnotation('result', 'error');
      try {
        subsegment.addError(error);
      } catch (e) {
        // Ignore X-Ray errors
      }
    }
    
    // Log error using Winston logger
    logError(error, requestId, null, { 
      operation: 'user_registration', 
      email 
    });
    
    let errorMessage = "Registration Failed";
    let statusCode = 500;
    
    if (error.name == "UsernameExistsException") {
      errorMessage = "User with this email already exists";
      statusCode = 409;
      logSecurity('duplicate_registration_attempt', null, requestId, { email });
    } else if (error.name=="InvalidPasswordException") {
      errorMessage = "Password does not meet requirements";
      statusCode = 400;
      logSecurity('invalid_password_policy', null, requestId, { email });
    } else if (error.name === "InvalidParameterException") {
      errorMessage = "Invalid input parameters";
      statusCode = 400;
    }

    logAuth('registration_failed', null, email, requestId, false, error);
    closeSubsegment(subsegment);

    res.status(statusCode).json({
      error: errorMessage,
      requestId
    });
  }
});

// Auth Status Route (Protected)
app.get("/auth/status", authenticateToken, (req, res) => {
  const segment = getSegment();
  if (segment) {
    segment.addAnnotation('endpoint', 'auth_status');
    segment.addAnnotation('user_id', req.user.userId);
  }
  
  res.json({ 
    authenticated: true,
    user: req.user,
    message: "Token is valid",
    requestId: req.requestId
  });
});

// Get User Profile (Protected)
app.get("/users/:userId", authenticateToken, async (req, res) => {
  const subsegment = addSubsegment('get-user-profile');
  
  try {
    // Check if user is accessing their own profile
    if (req.user.userId !== req.params.userId) {
      logSecurity('unauthorized_profile_access', req.user.userId, req.requestId, {
        requestedUserId: req.params.userId,
        actualUserId: req.user.userId
      });
      
      if (subsegment) {
        subsegment.addAnnotation('result', 'unauthorized');
      }
      closeSubsegment(subsegment);
      return res.status(403).json({ 
        error: 'Access denied: You can only access your own profile',
        requestId: req.requestId 
      });
    }

    const startTime = Date.now();
    const params = {
      TableName: USERS_TABLE,
      Key: {
        userId: req.params.userId,
      },
    };

    const command = new GetCommand(params);
    const { Item } = await docClient.send(command);
    const duration = Date.now() - startTime;
    
    // Log database operation
    logDatabase('get_user_profile', USERS_TABLE, req.user.userId, req.requestId, true);
    logPerformance('dynamodb_get_item', duration, req.requestId, req.user.userId);
    
    if (subsegment) {
      subsegment.addAnnotation('result', Item ? 'found' : 'not_found');
      subsegment.addMetadata('database', { duration, found: !!Item });
    }
    
    if (Item) {
      const { userId, name, email, createdAt, updatedAt } = Item;
      logBusiness('profile_retrieved', req.user.userId, req.requestId, { userId });
      
      closeSubsegment(subsegment);
      res.json({ userId, name, email, createdAt, updatedAt, requestId: req.requestId });
    } else {
      closeSubsegment(subsegment);
      res.status(404).json({ 
        error: 'User profile not found',
        message: 'Use POST /users to create your profile',
        requestId: req.requestId
      });
    }
    
  } catch (error) {
    if (subsegment) {
      try {
        subsegment.addError(error);
      } catch (e) {
        // Ignore X-Ray errors
      }
    }
    logError(error, req.requestId, req.user.userId, { operation: 'get_user_profile' });
    logDatabase('get_user_profile', USERS_TABLE, req.user.userId, req.requestId, false, error);
    
    closeSubsegment(subsegment);
    res.status(500).json({ error: "Could not retrieve user", requestId: req.requestId });
  }
});

// Create/Update User Profile (Protected)
app.post("/users", authenticateToken, async (req, res) => {
  const subsegment = addSubsegment('create-user-profile');
  
  try {
    const { name } = req.body;
    
    if (typeof name !== "string" || name.trim().length === 0) {
      if (subsegment) {
        subsegment.addAnnotation('result', 'validation_failed');
      }
      closeSubsegment(subsegment);
      return res.status(400).json({ 
        error: '"name" must be a non-empty string',
        requestId: req.requestId 
      });
    }

    const startTime = Date.now();
    const params = {
      TableName: USERS_TABLE,
      Item: { 
        userId: req.user.userId,
        name: name.trim(),
        email: req.user.email,
        username: req.user.username,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      },
    };

    const command = new PutCommand(params);
    await docClient.send(command);
    const duration = Date.now() - startTime;
    
    // Log using Winston logger
    logDatabase('create_user_profile', USERS_TABLE, req.user.userId, req.requestId, true);
    logBusiness('profile_created', req.user.userId, req.requestId, { name: name.trim() });
    logPerformance('dynamodb_put_item', duration, req.requestId, req.user.userId);
    
    if (subsegment) {
      subsegment.addAnnotation('result', 'success');
      subsegment.addMetadata('database', { duration });
    }
    closeSubsegment(subsegment);
    
    res.json({ 
      userId: req.user.userId, 
      name: name.trim(),
      email: req.user.email,
      username: req.user.username,
      message: "Profile created/updated successfully",
      requestId: req.requestId
    });
    
  } catch (error) {
    if (subsegment) {
      try {
        subsegment.addError(error);
      } catch (e) {
        // Ignore X-Ray errors
      }
    }
    logError(error, req.requestId, req.user.userId, { operation: 'create_user_profile' });
    logDatabase('create_user_profile', USERS_TABLE, req.user.userId, req.requestId, false, error);
    
    closeSubsegment(subsegment);
    res.status(500).json({ error: "Could not create/update user profile", requestId: req.requestId });
  }
});

// Get Current User Profile (Protected)
app.get("/profile", authenticateToken, async (req, res) => {
  const subsegment = addSubsegment('get-current-profile');
  
  try {
    const startTime = Date.now();
    const params = {
      TableName: USERS_TABLE,
      Key: {
        userId: req.user.userId,
      },
    };

    const command = new GetCommand(params);
    const { Item } = await docClient.send(command);
    const duration = Date.now() - startTime;
    
    // Log database operation
    logDatabase('get_current_profile', USERS_TABLE, req.user.userId, req.requestId, true);
    logPerformance('dynamodb_get_item', duration, req.requestId, req.user.userId);
    
    if (subsegment) {
      subsegment.addAnnotation('result', Item ? 'database_profile' : 'cognito_profile');
      subsegment.addMetadata('database', { duration, found: !!Item });
    }
    closeSubsegment(subsegment);
    
    if (Item) {
      const { userId, name, email, username, createdAt, updatedAt } = Item;
      res.json({ 
        userId, 
        name, 
        email, 
        username,
        createdAt, 
        updatedAt,
        source: "database",
        requestId: req.requestId
      });
    } else {
      res.json({ 
        userId: req.user.userId,
        email: req.user.email,
        username: req.user.username,
        name: req.user.name,
        source: "cognito",
        message: "Profile not created yet. Use POST /users to create profile.",
        requestId: req.requestId
      });
    }
    
  } catch (error) {
    if (subsegment) {
      try {
        subsegment.addError(error);
      } catch (e) {
        // Ignore X-Ray errors
      }
    }
    logError(error, req.requestId, req.user.userId, { operation: 'get_current_profile' });
    logDatabase('get_current_profile', USERS_TABLE, req.user.userId, req.requestId, false, error);
    
    closeSubsegment(subsegment);
    res.status(500).json({ error: "Could not retrieve profile", requestId: req.requestId });
  }
});

// Protected Routes Demo
app.get("/protected", authenticateToken, (req, res) => {
  const segment = getSegment();
  if (segment) {
    segment.addAnnotation('endpoint', 'protected_demo');
    segment.addAnnotation('user_id', req.user.userId);
  }
  
  logBusiness('protected_route_access', req.user.userId, req.requestId, { endpoint: '/protected' });
  
  res.json({
    message: "This is a protected route - you're authenticated!",
    user: req.user,
    timestamp: new Date().toISOString(),
    requestId: req.requestId
  });
});

// 404 Handler
app.use((req, res, next) => {
  logSecurity('404_not_found', req.user?.userId || null, req.requestId, {
    path: req.path,
    method: req.method,
    userAgent: req.get('User-Agent')
  });
  
  return res.status(404).json({
    error: "Not Found",
    path: req.path,
    method: req.method,
    message: "This endpoint does not exist",
    requestId: req.requestId
  });
});

// Your Custom Error Logging Middleware (must be before X-Ray close)
app.use(errorLoggin);

// X-Ray close segment middleware (conditional, must be last)
app.use(xrayCloseMiddleware);

// Export handler
exports.handler = serverless(app);