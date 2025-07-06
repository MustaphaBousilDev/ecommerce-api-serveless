const { SignUpCommand } = require("@aws-sdk/client-cognito-identity-provider");
const { cognitoClient, USER_POOL_CLIENT_ID } = require('../config/aws');

class CognitoService {
    async createUser(email, password, userAttributes){
        const params = {
            ClientId: USER_POOL_CLIENT_ID,
            Username: email, 
            Password: password,
            userAttributes: userAttributes
        }
        // Add SECRET_HASH if client secret exists
        const APP_CLIENT_SECRET = process.env.USER_POOL_CLIENT_SECRET;
        if(APP_CLIENT_SECRET) {
            const crypto = require('crypto')
            const secretHash = crypto.createHmac('sha256', APP_CLIENT_SECRET)
              .update(email + USER_POOL_CLIENT_ID)
              .digest('base64');
            params.SecretHash = secretHash;
        }
        const command = new SignUpCommand(params);
        return await cognitoClient.send(command);
    }
}
module.exports = new CognitoService();