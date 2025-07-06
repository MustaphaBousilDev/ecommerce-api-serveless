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
}
module.exports = new AuthService();