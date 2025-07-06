const authService = require('../services/authService');
const { logBusiness, logAuth, logError } = require('../utils/logger');

class AuthController {
  async register(req, res) {
    const { email, password, name, phone, address } = req.body;
    const requestId = req.requestId;
    
    try {
      // Log business activity
      logBusiness('registration_attempt', null, requestId, { email });
      
      const startTime = Date.now();
      
      // Call service layer
      const result = await authService.registerUser({
        email,
        password,
        name,
        phone,
        address
      });
      
      const duration = Date.now() - startTime;
      
      // Log success
      logAuth('user_registered', result.userId, email, requestId, true);
      logBusiness('registration_success', result.userId, requestId, { email });
      
      // Return success response
      res.status(201).json({
        success: true,
        message: "User registered successfully",
        data: {
          userId: result.userId,
          email: result.email,
          confirmationRequired: result.confirmationRequired,
          nextStep: result.confirmationRequired ? "confirm_email" : "login"
        },
        requestId,
        duration: `${duration}ms`
      });
      
    } catch (error) {
      // Log error
      logError(error, requestId, null, { operation: 'register', email });
      
      // Handle different error types
      let statusCode = 500;
      let message = "Registration failed";
      
      if (error.name === "UsernameExistsException") {
        statusCode = 409;
        message = "User with this email already exists";
      } else if (error.name === "InvalidPasswordException") {
        statusCode = 400;
        message = "Password does not meet requirements";
      } else if (error.name === "ValidationError") {
        statusCode = 400;
        message = error.message;
      }
      
      res.status(statusCode).json({
        success: false,
        error: message,
        errorType: error.name,
        requestId
      });
    }
  }
}

module.exports = new AuthController();