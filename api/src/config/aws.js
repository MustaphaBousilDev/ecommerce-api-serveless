const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient } = require("@aws-sdk/lib-dynamodb");
const { CognitoIdentityProviderClient } = require("@aws-sdk/client-cognito-identity-provider");
const { isXRayAvailable, AWSXRay } = require('./xray');

// Environment Variables
const USERS_TABLE = process.env.USERS_TABLE;
const USER_POOL_ID = process.env.USER_POOL_ID;
const USER_POOL_CLIENT_ID = process.env.USER_POOL_CLIENT_ID;
const AWS_REGION = process.env.AWS_REGION_NAME || 'us-east-1';

// AWS SDK v3 Clients with conditional X-Ray tracing
let dynamoClient, cognitoClient;

if (isXRayAvailable) {
  dynamoClient = AWSXRay.captureAWSv3Client(new DynamoDBClient({
    region: AWS_REGION
  }));
  cognitoClient = AWSXRay.captureAWSv3Client(new CognitoIdentityProviderClient({
    region: AWS_REGION,
  }));
} else {
  dynamoClient = new DynamoDBClient({
    region: AWS_REGION
  });
  cognitoClient = new CognitoIdentityProviderClient({
    region: AWS_REGION,
  });
}

const docClient = DynamoDBDocumentClient.from(dynamoClient);

module.exports = {
  dynamoClient,
  docClient,
  cognitoClient,
  USERS_TABLE,
  USER_POOL_ID,
  USER_POOL_CLIENT_ID,
  AWS_REGION
};