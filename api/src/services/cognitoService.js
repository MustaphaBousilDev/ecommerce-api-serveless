const {
    SignUpCommand, 
    ConfirmSignUpCommand, 
    InitiateAuthCommand, 
    GlobalSignOutCommand, 
    ResendConfirmationCodeCommand, 
    ForgotPasswordCommand, 
    ConfirmForgotPasswordCommand, 
    ChangePasswordCommand, 
    RespondToAuthChallengeCommand,
    AdminInitiateAuthCommand,
} = require("@aws-sdk/client-cognito-identity-provider");
const { cognitoClient, USER_POOL_CLIENT_ID } = require('../config/aws');
const { param } = require("express-validator");


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
    async confirmUser(email, confirmationCode) {
        const params = {
        ClientId: USER_POOL_CLIENT_ID,
        Username: email,
        ConfirmationCode: confirmationCode
        };
        
        // Add SECRET_HASH if client secret exists
        const APP_CLIENT_SECRET = process.env.USER_POOL_CLIENT_SECRET;
        if (APP_CLIENT_SECRET) {
        const crypto = require('crypto');
        const secretHash = crypto.createHmac('sha256', APP_CLIENT_SECRET)
            .update(email + USER_POOL_CLIENT_ID)
            .digest('base64');
        params.SecretHash = secretHash;
        }
        
        const command = new ConfirmSignUpCommand(params);
        return  cognitoClient.send(command);
    }
    async authenticateUser(email, password) {
        const authParams = {
        ClientId: USER_POOL_CLIENT_ID,
        AuthFlow: 'USER_PASSWORD_AUTH',
        AuthParameters: {
            USERNAME: email,
            PASSWORD: password
        }
        };
        
        // Add SECRET_HASH if client secret exists
        const APP_CLIENT_SECRET = process.env.USER_POOL_CLIENT_SECRET;
        if (APP_CLIENT_SECRET) {
        const crypto = require('crypto');
        const secretHash = crypto.createHmac('sha256', APP_CLIENT_SECRET)
            .update(email + USER_POOL_CLIENT_ID)
            .digest('base64');
        authParams.AuthParameters.SECRET_HASH = secretHash;
        }
        
        const command = new InitiateAuthCommand(authParams);
        return await cognitoClient.send(command);
    }
    async logout(accessToken) {
        const params = {
            AccessToken: accessToken
        };
        const command = new GlobalSignOutCommand(params);
        return  cognitoClient.send(command);
    }
    async resendConfirmation(email){
        const params = {
            ClientId: process.env.USER_POOL_CLIENT_ID,
            Username: email
        }
        const command = new ResendConfirmationCodeCommand(params)
        return cognitoClient.send(command)
    }
    async forgotPassword(email){
        const params = {
            ClientId: USER_POOL_CLIENT_ID,
            Username: email,
        }
        const command = new ForgotPasswordCommand(params)
        const result = await cognitoClient.send(command)
        return result;
    }
    async resetPassword(attributes) {
        const params = {
            ClientId: USER_POOL_CLIENT_ID,
            ...attributes
        }
        const command = new ConfirmForgotPasswordCommand(params)
        const result = cognitoClient.send(command)
        return result;
    } 
    async changePassword(attr) {
      const params ={
        AccessToken: attr.accessToken,
        PreviousPassword: attr.currentPassword,
        ProposedPassword: attr.newPassword
      }
      const command = new ChangePasswordCommand(params)
      return cognitoClient.send(command)

    }
    async logoutAllDevices(accessToken) {
        const params = {
            AccessToken: accessToken
        }
        const command = new GlobalSignOutCommand(params)
        const result = cognitoClient.send(command)
        return result;
    }
    async refreshToken(refreshToken) {
        const params = {
            ClientId: USER_POOL_CLIENT_ID,
            AuthFlow: 'REFRESH_TOKEN_AUTH',
            AuthParameters: {
                REFRESH_TOKEN: refreshToken
            }
        }
        const APP_CLIENT_SECRET = process.env.USER_POOL_CLIENT_SECRET;
        if (APP_CLIENT_SECRET) {
            const crypto = require('crypto');
            // For refresh, use the refresh token to generate hash
            const secretHash = crypto.createHmac('sha256', APP_CLIENT_SECRET)
            .update(refreshToken + USER_POOL_CLIENT_ID)
            .digest('base64');
            params.AuthParameters.SECRET_HASH = secretHash;
        }
        const command = new InitiateAuthCommand(params)
        return cognitoClient.send(command)
    }
    async initiateBiometricChallenge(email) {
        const params = {
            ClientId: USER_POOL_CLIENT_ID,
            AuthFlow: 'CUSTOM_AUTH',
            AuthParameters: {
                USERNAME: email, 
                CHALLENGE_TYPE: 'BIOMETRIC'
            }
        }
        const APP_CLIENT_SECRET = process.env.USER_POOL_CLIENT_SECRET;
        if (APP_CLIENT_SECRET) {
            const crypto = require('crypto');
            const secretHash = crypto.createHmac('sha256', APP_CLIENT_SECRET)
                .update(email + USER_POOL_CLIENT_ID)
                .digest('base64');
            params.AuthParameters.SECRET_HASH = secretHash;
        }
        const command = new InitiateAuthCommand(params);
        return await cognitoClient.send(command);
    }
    async respondToBiometricChallenge(email, session, challengeResponse){
        const params = {
            ClientId: USER_POOL_CLIENT_ID,
            ChallengeName: 'CUSTOM_CHALLENGE',
            Session: session,
            ChallengeResponses: {
                USERNAME: email, 
                ANSWER: challengeResponse
            }
        }
        const command = new RespondToAuthChallengeCommand(param)
        return cognitoClient.send(command)
    }
    async generateTemporaryPassword(email) {
        const crypto = require('crypto')
        return crypto.randomBytes(32).toString('hex')
    }
    async adminAuthenticateUser(email) {
    try {
        // For biometric-authenticated users, we use admin authentication
        // This requires admin privileges but bypasses password validation
        
        const params = {
        UserPoolId: process.env.USER_POOL_ID,
        ClientId: USER_POOL_CLIENT_ID,
        AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
        AuthParameters: {
            USERNAME: email,
            PASSWORD: await this.getBiometricTempPassword(email)
        }
        };

        // Add SECRET_HASH if needed
        const APP_CLIENT_SECRET = process.env.USER_POOL_CLIENT_SECRET;
        if (APP_CLIENT_SECRET) {
        const crypto = require('crypto');
        const secretHash = crypto.createHmac('sha256', APP_CLIENT_SECRET)
            .update(email + USER_POOL_CLIENT_ID)
            .digest('base64');
        params.AuthParameters.SECRET_HASH = secretHash;
        }

        const command = new AdminInitiateAuthCommand(params);
        return await cognitoClient.send(command);
        
    } catch (error) {
        // If admin auth fails, try alternative approach
        return await this.createBiometricSession(email);
    }
    }
    async getBiometricTempPassword(email) {
        const crypto = require('crypto');
        const seed = email + process.env.USER_POOL_CLIENT_SECRET + 'biometric';
        return crypto.createHash('sha256').update(seed).digest('hex').substring(0, 16);
    }
    async createBiometricSession(email) {
        try {
            const params = {
            ClientId: USER_POOL_CLIENT_ID,
            AuthFlow: 'CUSTOM_AUTH',
            AuthParameters: {
                USERNAME: email,
                CHALLENGE_TYPE: 'BIOMETRIC_VERIFIED'
            }
            };

            const command = new InitiateAuthCommand(params);
            return await cognitoClient.send(command);
            
        } catch (error) {
            throw new Error(`Failed to create biometric session for ${email}: ${error.message}`);
        }
    }
}
module.exports = new CognitoService();