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
  async login(req, res) {
    const { email, password } = req.body;
    const requestId = req.requestId;
    
    try {
      logBusiness('login_attempt', null, requestId, { email });
      
      const startTime = Date.now();
      const result = await authService.loginUser({ email, password });
      const duration = Date.now() - startTime;
      
      logAuth('user_logged_in', result.user.userId, email, requestId, true);
      
      res.status(200).json({
        success: true,
        message: "Login successful",
        data: result,
        requestId,
        duration: `${duration}ms`
      });
      
    } catch (error) {
      logError(error, requestId, null, { operation: 'login', email });
      
      let statusCode = 500;
      let message = "Login failed";
      
      if (error.name === "NotAuthorizedException") {
        statusCode = 401;
        message = "Invalid email or password";
        logSecurity('login_invalid_credentials', null, requestId, { email });
      } else if (error.name === "UserNotFoundException") {
        statusCode = 404;
        message = "User not found";
        logSecurity('login_user_not_found', null, requestId, { email });
      } else if (error.name === "UserNotConfirmedException") {
        statusCode = 400;
        message = "Account not confirmed";
        logSecurity('login_unconfirmed_user', null, requestId, { email });
      }
      
      res.status(statusCode).json({
        success: false,
        error: message,
        errorType: error.name,
        requestId
      });
    }
  }
  async confirm(req, res) {
    const { email, confirmationCode } = req.body;
    const requestId = req.requestId;
    
    try {
      logBusiness('confirmation_attempt', null, requestId, { email });
      
      const startTime = Date.now();
      await authService.confirmUser({ email, confirmationCode });
      const duration = Date.now() - startTime;
      
      logBusiness('confirmation_success', null, requestId, { email });
      
      res.status(200).json({
        success: true,
        message: "Email confirmed successfully",
        data: {
          email,
          nextStep: "login"
        },
        requestId,
        duration: `${duration}ms`
      });
      
    } catch (error) {
      logError(error, requestId, null, { operation: 'confirm', email });
      
      let statusCode = 500;
      let message = "Email confirmation failed";
      
      if (error.name === "CodeMismatchException") {
        statusCode = 400;
        message = "Invalid confirmation code";
      } else if (error.name === "ExpiredCodeException") {
        statusCode = 400;
        message = "Confirmation code has expired";
      }
      
      res.status(statusCode).json({
        success: false,
        error: message,
        errorType: error.name,
        requestId
      });
    }
  }
  async logout(req,res) {
    const requestedId = req.requestId;

    try {
      const startTime = Date.now()
      const authHeader = req.headers['authorization']
      const accessToken = authHeader && authHeader.split(' ')[1]
      if (!accessToken) {
        return res.status(400).json({
          success: false, 
          error: 'Access token required', 
          requestedId
        })
      }
      await authService.logout(accessToken)
      const duration = Date.now()-startTime
      res.status(200).json({
          success: true,
          message: "Logout successful",
          requestedId,
          duration: `${duration}ms`
      });
    } catch(error) {
      let statusCode = 500;
      let message = "LogOut failed";
      if (error.name === "NotAuthorizedException") {
        statusCode = 401;
        message = "Invalid or expired token";
      }
      res.status(statusCode).json({
        success: false,
        error: message,
        errorType: error.name,
        requestedId
      });
    }
  }
}

module.exports = new AuthController();