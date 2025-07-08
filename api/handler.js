const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} = require("@aws-sdk/lib-dynamodb");
const { SignUpCommand, CognitoIdentityProviderClient, ConfirmSignUpCommand, ResendConfirmationCodeCommand, ForgotPasswordCommand, ConfirmForgotPasswordCommand, InitiateAuthCommand } = require("@aws-sdk/client-cognito-identity-provider");
const authRoutes = require('./src/routers/authRouter');
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
} = require('./src/utils/logger');
const { requestLoggin } = require("./src/middlewares/logger");

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

console.log('Environment variables loaded:', {
  USERS_TABLE: USERS_TABLE ? 'set' : 'missing',
  USER_POOL_ID: USER_POOL_ID ? 'set' : 'missing',
  USER_POOL_CLIENT_ID: USER_POOL_CLIENT_ID ? 'set' : 'missing',
  AWS_REGION: AWS_REGION ? 'set' : 'missing'
});

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
    region: 'us-east-1',
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
app.use(requestLoggin);   
        // Your custom request logging middleware


//Routers
//app.use('/auth', authRoutes);


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
app.post("/test-confirm", async (req, res) => {
  try {
    const { CognitoIdentityProviderClient, ConfirmSignUpCommand } = require("@aws-sdk/client-cognito-identity-provider");
    
    const cognitoClient = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION_NAME || 'us-east-1'
    });
    
    const { email, confirmationCode } = req.body;
    
    const params = {
      ClientId: process.env.USER_POOL_CLIENT_ID,
      Username: email,
      ConfirmationCode: confirmationCode
    };
    
    const command = new ConfirmSignUpCommand(params);
    await cognitoClient.send(command);
    
    res.json({
      message: "Email confirmed successfully",
      nextStep: "login"
    });
    
  } catch (error) {
    console.error("Confirmation error:", error);
    res.status(500).json({
      error: error.message,
      name: error.name
    });
  }
});
// Health Check Route (Public)
app.get("/health", (req, res) => {
  console.log('Detailed health check request received');
  res.json({ 
    status: "healthy",
    timestamp: new Date().toISOString(),
    environment: {
      userPoolId: USER_POOL_ID ? "configured" : "missing",
      clientId: USER_POOL_CLIENT_ID ? "configured" : "missing",
      region: AWS_REGION,
      usersTable: USERS_TABLE
    }
  });
});


app.post("/auth/confirms", async (req, res) => {
  console.log('Confirmation endpoint hit');
  
  try {
    // 1. FIRST: Extract variables from request body
    const { email, confirmationCode } = req.body;
    console.log('Email:', email, 'Code:', confirmationCode);
    
    // 2. THEN: Validate them
    if (!email || !confirmationCode) {
      console.log('Validation failed - missing email or code');
      return res.status(400).json({
        error: 'Email and confirmation code are required'
      });
    }
    
    // 3. Import Cognito (same as working version)
    const { CognitoIdentityProviderClient, ConfirmSignUpCommand } = require("@aws-sdk/client-cognito-identity-provider");
    
    const cognitoClient = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION_NAME || 'us-east-1'
    });
    
    console.log('Starting confirmation process...');
    const startTime = Date.now();
    
    const params = {
      ClientId: process.env.USER_POOL_CLIENT_ID,
      Username: email,
      ConfirmationCode: confirmationCode
    };
    
    console.log('Sending confirmation command...');
    const command = new ConfirmSignUpCommand(params);
    await cognitoClient.send(command);
    
    const duration = Date.now() - startTime;
    console.log(`Confirmation successful in ${duration}ms`);
    
    res.status(200).json({
      message: 'Email confirmed successfully',
      email: email,
      nextStep: "login",
      duration: `${duration}ms`
    });
    
  } catch(error) {
    console.error('Confirmation error:', error);
    
    let errorMessage = "Email confirmation failed";
    let statusCode = 500;
    
    // Handle specific Cognito errors
    if (error.name === "CodeMismatchException") {
      errorMessage = "Invalid confirmation code";
      statusCode = 400;
    } else if (error.name === "ExpiredCodeException") {
      errorMessage = "Confirmation code has expired";
      statusCode = 400;
    } else if (error.name === "UserNotFoundException") {
      errorMessage = "User not found";
      statusCode = 404;
    } else if (error.name === "NotAuthorizedException") {
      errorMessage = "User is already confirmed";
      statusCode = 400;
    } else if (error.name === "LimitExceededException") {
      errorMessage = "Too many attempts. Please try again later";
      statusCode = 429;
    }
    
    res.status(statusCode).json({
      error: errorMessage,
      errorType: error.name
    });
  }
});
app.post("/auth/resend_confirmation", async (req, res)=> {
  console.log('Resend confirmation endpoint hit');
  
  try {
  const { email } = req.body 
  const requestedId = req.requestId;
  logBusiness('resend_confirmation_attempt', null, requestedId, { email });
  if(!email){
    logSecurity('resend_confirmation_invalid_input', null, requestedId, { 
      missing: { email: !email }
    });
    
    
    return res.status(400).json({
      error: 'Email is required'
    });
  }
  const { CognitoIdentityProviderClient, ResendConfirmationCodeCommand } = require("@aws-sdk/client-cognito-identity-provider");
  const cognitoClient = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION_NAME || 'us-east-1'
  });
  console.log('Starting resend confirmation process...');
  const startTime = Date.now();
  const params = {
      ClientId: process.env.USER_POOL_CLIENT_ID,
      Username: email
  };
  console.log('Sending resend confirmation command...');
  const command = new ResendConfirmationCodeCommand(params);
  const result = await cognitoClient.send(command);
  const duration  = Date.now() - startTime;
  console.log(`Resend confirmation successful in ${duration}ms`);
  res.status(200).json({
      message: "Confirmation code sent successfully",
      email: email,
      deliveryDetails: {
        destination: result.CodeDeliveryDetails?.Destination,
        deliveryMedium: result.CodeDeliveryDetails?.DeliveryMedium
      },
      nextStep: "confirm_email",
      duration: `${duration}ms`
  });
  } catch(error) {
      console.error('Resend confirmation error:', error);
    
    let errorMessage = "Failed to resend confirmation code";
    let statusCode = 500;
    
    // Handle specific Cognito errors
    if (error.name === "UserNotFoundException") {
      errorMessage = "User not found";
      statusCode = 404;
    } else if (error.name === "InvalidParameterException") {
      errorMessage = "User is already confirmed";
      statusCode = 400;
    } else if (error.name === "LimitExceededException") {
      errorMessage = "Too many resend attempts. Please try again later";
      statusCode = 429;
    } else if (error.name === "NotAuthorizedException") {
      errorMessage = "User account is disabled or deleted";
      statusCode = 403;
    }
    
    res.status(statusCode).json({
      error: errorMessage,
      errorType: error.name
    });
  }
})
app.post("/auth/login", async (req, res)=> {
  const { email, password } = req.body;
  const requestId = req.requestId;

  try {
    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required',
        requestId
      });
    }
    const startTime = Date.now();
    let authParams = {
      ClientId: USER_POOL_CLIENT_ID,
      AuthFlow: 'USER_PASSWORD_AUTH',
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password
      }
    };
    const APP_CLIENT_SECRET = process.env.USER_POOL_CLIENT_SECRET;
    if (APP_CLIENT_SECRET) {
      const crypto = require('crypto');
      const secretHash = crypto
        .createHmac('sha256', APP_CLIENT_SECRET)
        .update(email + USER_POOL_CLIENT_ID)
        .digest('base64');
      
      authParams.AuthParameters.SECRET_HASH = secretHash;
    }
    console.log('Attempting login for:', email);
    const command = new InitiateAuthCommand(authParams);
    const authResult = await cognitoClient.send(command);
    const duration = Date.now() - startTime;
    
    console.log('Auth result:', authResult.ChallengeName || 'SUCCESS');
    if (authResult.ChallengeName) {
      // Handle challenges (MFA, password reset, etc.)
      const challengeResponse = handleAuthChallenge(authResult, email, requestId);
      
      return res.status(200).json(challengeResponse);
    }
    const {
      AccessToken,
      IdToken,
      RefreshToken,
      TokenType = 'Bearer',
      ExpiresIn = 3600
    } = authResult.AuthenticationResult;
    
    // Decode ID token to get user info (basic decode, not verification)
    const idTokenPayload = JSON.parse(Buffer.from(IdToken.split('.')[1], 'base64').toString());
    res.status(200).json({
      message: "Login successful",
      user: {
        userId: idTokenPayload.sub,
        email: idTokenPayload.email,
        name: idTokenPayload.name || idTokenPayload.given_name || 'User',
        username: idTokenPayload.preferred_username || idTokenPayload.email,
        emailVerified: idTokenPayload.email_verified
      },
      tokens: {
        accessToken: AccessToken,
        idToken: IdToken,
        refreshToken: RefreshToken,
        tokenType: TokenType,
        expiresIn: ExpiresIn,
        expiresAt: new Date(Date.now() + (ExpiresIn * 1000)).toISOString()
      },
      requestId,
      duration: `${duration}ms`
    });
  } catch(error) {
      let errorMessage = "Login failed";
    let statusCode = 500;
    let action = "try_again";
    
    // Handle specific Cognito errors
    if (error.name === "NotAuthorizedException") {
      errorMessage = "Invalid email or password";
      statusCode = 401;
      action = "check_credentials";
      logSecurity('login_invalid_credentials', null, requestId, { email });
      logAuth('login_failed', null, email, requestId, false, error);
    } else if (error.name === "UserNotFoundException") {
      errorMessage = "User not found";
      statusCode = 404;
      action = "register";
      logSecurity('login_user_not_found', null, requestId, { email });
    } else if (error.name === "UserNotConfirmedException") {
      errorMessage = "Account not confirmed";
      statusCode = 400;
      action = "confirm_account";
      logSecurity('login_unconfirmed_user', null, requestId, { email });
      
      // Try to resend confirmation code
      try {
        const { ResendConfirmationCodeCommand } = require("@aws-sdk/client-cognito-identity-provider");
        const resendParams = {
          ClientId: USER_POOL_CLIENT_ID,
          Username: email.trim().toLowerCase()
        };
        
        const resendCommand = new ResendConfirmationCodeCommand(resendParams);
        const resendResult = await cognitoClient.send(resendCommand);
        
        closeSubsegment(subsegment);
        return res.status(400).json({
          error: errorMessage,
          errorType: error.name,
          action,
          message: "Please confirm your account first. We've sent you a new confirmation code.",
          deliveryDetails: resendResult.CodeDeliveryDetails,
          nextStep: "Use POST /auth/confirm to confirm your account",
          requestId
        });
      } catch (resendError) {
        console.log('Failed to resend confirmation code:', resendError.message);
      }
    } else if (error.name === "TooManyRequestsException" || error.name === "LimitExceededException") {
      errorMessage = "Too many login attempts. Please try again later";
      statusCode = 429;
      action = "wait_and_retry";
      logSecurity('login_rate_limit', null, requestId, { email });
    } else if (error.name === "InvalidParameterException") {
      errorMessage = "Invalid input parameters";
      statusCode = 400;
      action = "check_input";
    } else if (error.name === "PasswordResetRequiredException") {
      errorMessage = "Password reset required";
      statusCode = 400;
      action = "reset_password";
      logSecurity('login_password_reset_required', null, requestId, { email });
    }
    res.status(statusCode).json({
      error: errorMessage,
      errorType: error.name,
      action,
      requestId,
      debug: {
        message: error.message
      }
    });
  }
})
function handleAuthChallenge(authResult, email, requestId) {
  const challengeName = authResult.ChallengeName;
  const session = authResult.Session;
  
  console.log('Handling challenge:', challengeName);
  
  switch (challengeName) {
    case 'NEW_PASSWORD_REQUIRED':
      logSecurity('login_new_password_required', null, requestId, { email });
      return {
        challenge: "NEW_PASSWORD_REQUIRED",
        message: "New password required",
        session: session,
        requiredAttributes: authResult.ChallengeParameters?.requiredAttributes,
        action: "set_new_password",
        nextStep: "Use POST /auth/respond-to-challenge with new password",
        requestId
      };
      
    case 'MFA_SETUP':
      logSecurity('login_mfa_setup_required', null, requestId, { email });
      return {
        challenge: "MFA_SETUP",
        message: "MFA setup required",
        session: session,
        action: "setup_mfa",
        nextStep: "Set up MFA authentication",
        requestId
      };
      
    case 'SMS_MFA':
      logSecurity('login_sms_mfa_required', null, requestId, { email });
      return {
        challenge: "SMS_MFA",
        message: "SMS verification required",
        session: session,
        action: "enter_sms_code",
        nextStep: "Enter the SMS code sent to your phone",
        requestId
      };
      
    case 'SOFTWARE_TOKEN_MFA':
      logSecurity('login_software_token_mfa_required', null, requestId, { email });
      return {
        challenge: "SOFTWARE_TOKEN_MFA",
        message: "Software token verification required",
        session: session,
        action: "enter_token_code",
        nextStep: "Enter code from your authenticator app",
        requestId
      };
      
    default:
      logSecurity('login_unknown_challenge', null, requestId, { email, challengeName });
      return {
        challenge: challengeName,
        message: "Additional authentication required",
        session: session,
        action: "contact_support",
        nextStep: "Contact support for assistance",
        requestId
      };
  }
}

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

//forgot password
app.post('/auth/forgot-password', async (req,res) => {
  const { email } = req.body
  const requestedId = req.requestId;
  logBusiness('forgot_password_attempt', null, requestedId, { email });
  try {
    if (!email || !email.trim()) {
      logSecurity('forgot_password_invalid_input', null, requestedId, { 
        missing: { email: !email }
      });
      
      return res.status(400).json({
        error: 'Email is required',
        requestedId
      });
    }
    const startTime = Date.now()
    
    const { CognitoIdentityProviderClient, ForgotPasswordCommand } = require("@aws-sdk/client-cognito-identity-provider");
    const cognitoClient = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION_NAME || 'us-east-1'
    });
    const params = {
      ClientId: USER_POOL_CLIENT_ID,
      Username: email
    };
    const command = new ForgotPasswordCommand(params)
    const result = await cognitoClient.send(command)
    const duration = Date.now() - startTime
    logBusiness('forgot_password_success', null, requestedId, {
      email: email.trim().toLowerCase(),
      deliveryMedium: result.CodeDeliveryDetails?.DeliveryMedium,
      destination: result.CodeDeliveryDetails?.Destination
    });

    res.status(200).json({
      message: 'Password reset code sent successfully', 
      email: email.trim().toLowerCase(),
      deliveryDetails: {
        destination: result.CodeDeliveryDetails?.Destination,
        deliveryMedium: result.CodeDeliveryDetails?.DeliveryMedium
      },
      nextStep: "reset_password",
      instructions: "Check your email for the verification code and use it with the new password in the reset-password endpoint",
      requestedId,
      duration: `${duration}ms`
    })

  } catch (error){
    logError(error, requestedId, null, { 
      operation: 'forgot_password', 
      email 
    });
    let errorMessage = "Failed to send password reset code";
    let statusCode = 500;
    if (error.name === "UserNotFoundException") {
      errorMessage = "User not found";
      statusCode = 404;
      logSecurity('forgot_password_user_not_found', null, requestId, { email });
    } else if (error.name === "InvalidParameterException") {
      errorMessage = "Invalid input parameters";
      statusCode = 400;
    } else if (error.name === "LimitExceededException") {
      errorMessage = "Too many password reset attempts. Please try again later";
      statusCode = 429;
      logSecurity('forgot_password_rate_limit', null, requestId, { email });
    } else if (error.name === "NotAuthorizedException") {
      errorMessage = "User account is disabled or not confirmed";
      statusCode = 403;
      logSecurity('forgot_password_unauthorized', null, requestId, { email });
    } else if (error.name === "UserNotConfirmedException") {
      errorMessage = "User account is not confirmed. Please confirm your account first";
      statusCode = 400;
    }
    res.status(statusCode).json({
      error: errorMessage,
      errorType: error.name,
      requestedId
    });
  } 
})

//reset password
app.post('/auth/reset-password', async (req, res)=> {
  const { email, confirmationCode, newPassword } = req.body;
  const requestId = req.requestId;
  try {
    if (!email || !confirmationCode || !newPassword) {
      return res.status(400).json({
        error: 'Email, confirmation code, and new password are required',
        requestId
      });
    }
    if (newPassword.length < 8) {
      logSecurity('reset_password_weak_password', null, requestId, { email });
      return res.status(400).json({
        error: 'New password must be at least 8 characters long',
        requestId
      });
    }
    const startTime = Date.now();
    
    const params = {
      ClientId: USER_POOL_CLIENT_ID,
      Username: email.trim().toLowerCase(),
      ConfirmationCode: confirmationCode.trim(),
      Password: newPassword
    };
    const command = new ConfirmForgotPasswordCommand(params);
    await cognitoClient.send(command);
    const duration = Date.now() - startTime;
    logBusiness('password_reset_completed', null, requestId, {
      email: email.trim().toLowerCase()
    });
    res.status(200).json({
      message: "Password reset successfully",
      email: email.trim().toLowerCase(),
      nextStep: "login",
      instructions: "You can now login with your new password",
      requestId,
      duration: `${duration}ms`
    });
  } catch(error) {
    let errorMessage = "Password reset failed";
    let statusCode = 500;
    
    // Handle specific Cognito errors
    if (error.name === "CodeMismatchException") {
      errorMessage = "Invalid confirmation code";
      statusCode = 400;
      logSecurity('reset_password_invalid_code', null, requestId, { email });
    } else if (error.name === "ExpiredCodeException") {
      errorMessage = "Confirmation code has expired. Please request a new one";
      statusCode = 400;
      logSecurity('reset_password_expired_code', null, requestId, { email });
    } else if (error.name === "UserNotFoundException") {
      errorMessage = "User not found";
      statusCode = 404;
      logSecurity('reset_password_user_not_found', null, requestId, { email });
    } else if (error.name === "InvalidPasswordException") {
      errorMessage = "New password does not meet requirements";
      statusCode = 400;
      logSecurity('reset_password_invalid_password_policy', null, requestId, { email });
    } else if (error.name === "LimitExceededException") {
      errorMessage = "Too many attempts. Please try again later";
      statusCode = 429;
      logSecurity('reset_password_rate_limit', null, requestId, { email });
    } else if (error.name === "NotAuthorizedException") {
      errorMessage = "Invalid or expired confirmation code";
      statusCode = 400;
    } else if (error.name === "InvalidParameterException") {
      errorMessage = "Invalid input parameters";
      statusCode = 400;
    }
    res.status(statusCode).json({
      error: errorMessage,
      errorType: error.name,
      requestId
    });
  }
})

//change password
app.post("/auth/change-password",authenticateToken, async (req, res)=> {
  const { currentPassword, newPassword } = req.body;
  const requestId = req.requestId;
  const userId = req.user.userId;
  logBusiness('change_password_attempt', userId, requestId, { email: req.user.email });
  try {
     if (!currentPassword || !newPassword) {
      return res.status(400).json({
        error: 'Current password and new password are required',
        requestId
      });
     }
     if (newPassword.length < 8) {
      logSecurity('change_password_weak_password', userId, requestId, { email: req.user.email });
     
     
      return res.status(400).json({
        error: 'New password must be at least 8 characters long',
        requestId
      });
    }
    if (currentPassword === newPassword) {
      return res.status(400).json({
        error: 'New password must be different from current password',
        requestId
      });
    }
    const startTime = Date.now();
    const { ChangePasswordCommand } = require("@aws-sdk/client-cognito-identity-provider");
    const authHeader = req.headers['authorization'];
    const accessToken = authHeader && authHeader.split(' ')[1];
    
    const params = {
      AccessToken: accessToken,
      PreviousPassword: currentPassword,
      ProposedPassword: newPassword
    };

    const command = new ChangePasswordCommand(params);
    await cognitoClient.send(command);
    
    const duration = Date.now() - startTime;
    res.status(200).json({
      message: "Password changed successfully",
      user: {
        userId: req.user.userId,
        email: req.user.email
      },
      requestId,
      duration: `${duration}ms`
    });
  } catch(error) {
    let errorMessage = "Password change failed";
    let statusCode = 500;
    
    // Handle specific Cognito errors
    if (error.name === "NotAuthorizedException") {
      errorMessage = "Current password is incorrect";
      statusCode = 400;
      logSecurity('change_password_wrong_current_password', userId, requestId, { 
        email: req.user.email 
      });
    } else if (error.name === "InvalidPasswordException") {
      errorMessage = "New password does not meet requirements";
      statusCode = 400;
      logSecurity('change_password_invalid_password_policy', userId, requestId, { 
        email: req.user.email 
      });
    } else if (error.name === "LimitExceededException") {
      errorMessage = "Too many password change attempts. Please try again later";
      statusCode = 429;
      logSecurity('change_password_rate_limit', userId, requestId, { 
        email: req.user.email 
      });
    } else if (error.name === "InvalidParameterException") {
      errorMessage = "Invalid input parameters";
      statusCode = 400;
    }

    res.status(statusCode).json({
      error: errorMessage,
      errorType: error.name,
      requestId
    });
  }
})


app.post('/auth/logout-all', ()=> {})
app.post('/auth/user-info', ()=> {})
app.post('/auth/refresh', ()=> {})
app.post('/auth/update-user-attributes', ()=> {})
app.post('/auth/verify-user-attribute', ()=> {})
app.post('/auth/delete-user', ()=> {})
app.post('/auth/resend-attribute-verification', ()=> {})
//MFA
app.post('/auth/respond-to-challenge', ()=> {})
app.post('/auth/associate-software-token', ()=> {})
app.post('/auth/verify-software-token', ()=> {})
app.post('/auth/set-user-mfa-preference', ()=> {})
//ADMIN OPERATION
app.post('/auth/admin/create-user', ()=> {})
app.post('/auth/admin/delete-user', ()=> {})
app.post('/auth/admin/disable-user', ()=> {})
app.post('/auth/admin/enable-user ', ()=> {})
app.post('/auth/auth/admin/reset-password', ()=> {})
app.post('/auth/admin/users', ()=> {})
app.post('/auth/admin/user/:userId', ()=> {})
//GROUP MANAGEMENT
app.post('/auth/admin/create-group', ()=> {})
app.post('/auth/admin/add-user-to-group', ()=> {})
app.post('/auth/admin/remove-user-from-group', ()=> {})
app.post('/auth/admin/groups', ()=> {})
app.post('/auth/admin/user-groups/:userId', ()=> {})
//Utility Endpoints
app.post('/auth/password-policy', ()=> {})
app.post('/auth/check-user-exists', ()=> {})
app.post('/aauth/user-pool-info', ()=> {})

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