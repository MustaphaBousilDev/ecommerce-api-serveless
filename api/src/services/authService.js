const cognitoService = require('./cognitoService');

class AuthService {
    async registerUser(userData) {
        const { email, password, name, phone, address } = userData;
        
        try {
        // Clean and validate input
        const cleanEmail = email.trim().toLowerCase();
        
        // Business validation
        this._validateInput(cleanEmail, password, name);
        
        // Prepare user attributes
        const userAttributes = this._prepareUserAttributes(cleanEmail, name, phone, address);
        
        // Create user in Cognito
        const cognitoResult = await cognitoService.createUser(cleanEmail, password, userAttributes);
        
        // Return standardized response
        return {
            userId: cognitoResult.UserSub,
            email: cleanEmail,
            confirmationRequired: !cognitoResult.UserConfirmed
        };
        
        } catch (error) {
        throw error;
        }
    }
    async loginUser(loginData) {
    const { email, password } = loginData;
    
    try {
      const cleanEmail = email.trim().toLowerCase();
      
      // Validate input
      if (!cleanEmail || !password) {
        const error = new Error('Email and password are required');
        error.name = 'ValidationError';
        throw error;
      }
      
      // Authenticate with Cognito
      const authResult = await cognitoService.authenticateUser(cleanEmail, password);
      
      // Handle challenges if any
      if (authResult.ChallengeName) {
        return {
          challenge: authResult.ChallengeName,
          session: authResult.Session,
          challengeParameters: authResult.ChallengeParameters
        };
      }
      
      // Extract tokens and user info
      const tokens = authResult.AuthenticationResult;
      const userInfo = this._extractUserInfo(tokens.IdToken);
      
      return {
        user: userInfo,
        tokens: {
          accessToken: tokens.AccessToken,
          idToken: tokens.IdToken,
          refreshToken: tokens.RefreshToken,
          tokenType: 'Bearer',
          expiresIn: tokens.ExpiresIn,
          expiresAt: new Date(Date.now() + (tokens.ExpiresIn * 1000)).toISOString()
        }
      };
      
    } catch (error) {
      throw error;
    }
    }

    async confirmUser(confirmData) {
        const { email, confirmationCode } = confirmData;
        
        try {
        const cleanEmail = email.trim().toLowerCase();
        
        if (!cleanEmail || !confirmationCode) {
            const error = new Error('Email and confirmation code are required');
            error.name = 'ValidationError';
            throw error;
        }
        
        await cognitoService.confirmUser(cleanEmail, confirmationCode);
        
        } catch (error) {
          
        throw error;
        }
    }
    _validateInput(email, password, name) {
        if (!email || !password || !name) {
        const error = new Error('Email, password, and name are required');
        error.name = 'ValidationError';
        throw error;
        }
        
        if (password.length < 8) {
        const error = new Error('Password must be at least 8 characters long');
        error.name = 'ValidationError';
        throw error;
        }
        
        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
        const error = new Error('Invalid email format');
        error.name = 'ValidationError';
        throw error;
        }
    }
    _prepareUserAttributes(email, name, phone, address) {
        const attributes = [
        { Name: 'email', Value: email },
        { Name: 'name', Value: name.trim() },
        { Name: 'given_name', Value: name.trim().split(' ')[0] },
        { Name: 'family_name', Value: name.trim().split(' ').slice(1).join(' ') || name.trim().split(' ')[0] }
        ];
        
        if (phone) {
        attributes.push({ Name: 'phone_number', Value: phone });
        }
        
        if (address) {
        attributes.push({ Name: 'address', Value: address.trim() });
        } else {
        attributes.push({ Name: 'address', Value: 'Not provided' });
        }
        
        return attributes;
    }
    _extractUserInfo(idToken) {
    // Basic decode of ID token (not verification - that's handled by API Gateway)
    const payload = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString());
    
    return {
      userId: payload.sub,
      email: payload.email,
      name: payload.name || payload.given_name || 'User',
      username: payload.preferred_username || payload.email,
      emailVerified: payload.email_verified
    };
  }
}
module.exports = new AuthService();