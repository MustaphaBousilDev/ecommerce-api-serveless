const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} = require("@aws-sdk/lib-dynamodb");

const express = require("express");
const serverless = require("serverless-http");
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const { SignUpCommand, CognitoIdentityProviderClient } = require("@aws-sdk/client-cognito-identity-provider");
const AWSXRay = require('aws-xray-sdk-core');
// Environment Variables
const USERS_TABLE = process.env.USERS_TABLE;
const USER_POOL_ID = process.env.USER_POOL_ID;
const USER_POOL_CLIENT_ID = process.env.USER_POOL_CLIENT_ID;
const AWS_REGION = process.env.AWS_REGION_NAME;

const AWS = AWSXRay.captureAWS(require('aws-sdk'));

// DynamoDB Client Setup
const client = new DynamoDBClient();
const docClient = DynamoDBDocumentClient.from(client);

//Cognito Client Setup
const cognitoClient = new CognitoIdentityProviderClient({
  region: AWS_REGION,
})

// Cognito JWT Verifier Setup
const verifier = CognitoJwtVerifier.create({
  userPoolId: USER_POOL_ID,
  tokenUse: "access",
  clientId: USER_POOL_CLIENT_ID,
  
});

// JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    // Verify the JWT token
    const payload = await verifier.verify(token);
    
    // Add user info to request
    req.user = {
      userId: payload.sub,
      email: payload.email,
      username: payload.username,
      name: payload.name || payload.given_name || 'Unknown'
    };

    next();
  } catch (error) {
    console.log('JWT verification failed:', error.message);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Express App Setup
const app = express();
app.use(express.json());

// Health Check Route (Public)
app.get("/", (req, res) => {
  res.json({ 
    message: "E-commerce API is running",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
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

app.post("/auth/register", async (req,res)=> {
  const {email, password, name, phone, address} = req.body
  if (!email || !password || !name) {
    return res.status(400).json({
      error: 'Email, password and name are required'
    })
  }
  if (password.length < 8) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters long'
    })
  }
  try {
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
          Name: "address",  // Add this
          Value: address || "Not provided"
        }
      ]
    }
    if(phone) {
      params.UserAttributes.push({
        Name: "phone_number",
        Value: phone
      })
    }
    const command = new SignUpCommand(params)
    const result = await cognitoClient.send(command)
    res.status(201).json({
      message: "User registered successfully",
      userId: result.UserSub,
      email: email,
      confirmationRequired: !result.UserConfirmed,
      nextStep: result.UserConfirmed ? "login": "confirm_email"
    })
  }
  catch(error) {
    console.error("Registration error: ", error)
    let errorMessage = "Registration Failed"
    let statusCode = 500
    if (error.name == "UsernameExistsException") {
      errorMessage = "User with this email already exists"
      statusCode = 409
    } else if (error.name=="InvalidPasswordException") {
      errorMessage = "Password does not meet requirements"
      statusCode = 400
    } else if (error.name === "InvalidParameterException") {
      errorMessage = "Invalid input parameters";
      statusCode = 400;
    }

    res.status(statusCode).json({
      error: errorMessage
    })
  }
})

// Auth Status Route (Protected) - Test if token is valid
app.get("/auth/status", authenticateToken, (req, res) => {
  res.json({ 
    authenticated: true,
    user: req.user,
    message: "Token is valid"
  });
});

// Get User Profile (Protected)
app.get("/users/:userId", authenticateToken, async (req, res) => {
  const params = {
    TableName: USERS_TABLE,
    Key: {
      userId: req.params.userId,
    },
  };

  try {
    // Check if user is accessing their own profile
    if (req.user.userId !== req.params.userId) {
      return res.status(403).json({ error: 'Access denied: You can only access your own profile' });
    }

    const command = new GetCommand(params);
    const { Item } = await docClient.send(command);
    
    if (Item) {
      const { userId, name, email, createdAt, updatedAt } = Item;
      res.json({ userId, name, email, createdAt, updatedAt });
    } else {
      res.status(404).json({ 
        error: 'User profile not found',
        message: 'Use POST /users to create your profile'
      });
    }
  } catch (error) {
    console.log('Error retrieving user:', error);
    res.status(500).json({ error: "Could not retrieve user" });
  }
});

// Create/Update User Profile (Protected)
app.post("/users", authenticateToken, async (req, res) => {
  const { name } = req.body;
  
  if (typeof name !== "string" || name.trim().length === 0) {
    return res.status(400).json({ error: '"name" must be a non-empty string' });
  }

  const params = {
    TableName: USERS_TABLE,
    Item: { 
      userId: req.user.userId, // Use authenticated user's ID
      name: name.trim(),
      email: req.user.email,
      username: req.user.username,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    },
  };

  try {
    const command = new PutCommand(params);
    await docClient.send(command);
    res.json({ 
      userId: req.user.userId, 
      name: name.trim(),
      email: req.user.email,
      username: req.user.username,
      message: "Profile created/updated successfully"
    });
  } catch (error) {
    console.error('Error creating/updating user:', error);
    res.status(500).json({ error: "Could not create/update user profile" });
  }
});

// Get Current User Profile (Protected)
app.get("/profile", authenticateToken, async (req, res) => {
  const params = {
    TableName: USERS_TABLE,
    Key: {
      userId: req.user.userId,
    },
  };

  try {
    const command = new GetCommand(params);
    const { Item } = await docClient.send(command);
    
    if (Item) {
      const { userId, name, email, username, createdAt, updatedAt } = Item;
      res.json({ 
        userId, 
        name, 
        email, 
        username,
        createdAt, 
        updatedAt,
        source: "database"
      });
    } else {
      // User exists in Cognito but not in our database yet
      res.json({ 
        userId: req.user.userId,
        email: req.user.email,
        username: req.user.username,
        name: req.user.name,
        source: "cognito",
        message: "Profile not created yet. Use POST /users to create profile."
      });
    }
  } catch (error) {
    console.log('Error retrieving profile:', error);
    res.status(500).json({ error: "Could not retrieve profile" });
  }
});

// Protected Routes Demo
app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    message: "This is a protected route - you're authenticated!",
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

// 404 Handler (Keep this at the end)
app.use((req, res, next) => {
  return res.status(404).json({
    error: "Not Found",
    path: req.path,
    method: req.method,
    message: "This endpoint does not exist"
  });
});

// Export handler
exports.handler = serverless(app);