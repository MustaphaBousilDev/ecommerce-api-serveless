const authService = require('../services/authService');
const { logBusiness, logAuth, logError, logSecurity } = require('../utils/logger');

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
        //logSecurity('login_invalid_credentials', null, requestId, { email });
      } else if (error.name === "UserNotFoundException") {
        statusCode = 404;
        message = "User not found";
        //logSecurity('login_user_not_found', null, requestId, { email });
      } else if (error.name === "UserNotConfirmedException") {
        statusCode = 400;
        message = "Account not confirmed";
        //logSecurity('login_unconfirmed_user', null, requestId, { email });
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
  async forgotPassword(req, res) {
    const requestedId = req.requestId;
    const { email } = req.body;
    try {
      if(!email || !email.trim()){
        logSecurity('forgot_password_invalid_input', null, requestedId, { 
          missing: { email: !email }
        });
      
        return res.status(400).json({
          error: 'Email is required',
          requestedId
        });
      }
      const startTime = Date.now()
      const result = await authService.forgotPassword(email)
      const duration = Date.now() - startTime;
      res.status(200).json({
        message: "Password reset code send successfuly",
        email: email.trim().toLowerCase(),
        deliveryDetails: {
          destination: result.CodeDeliveryDetails?.Destination,
          deliveryMedium: result.CodeDeliveryDetails?.DeliveryMedium
        },
        nextStep: "reset_password",
        instruction: "Check your boite mail for the verification code and use it with the new password in the reset-password endpoint",
        requestedId,
        duration: `${duration}ms`
      })
    } catch(error) {
      console.error('forgot password error:', error);
      let errorMessage = "Failed to forgotPassword"
      let statusCode = 500
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
  }
  async resetPassword(req,res) {
    const requestedId = req.requestId;
    const { email } = req.body;
    const startDate = Date.now()
    const result = await authService.resetPassword(req.body)
    const duration  = Date.now() - startDate;
    res.status(200).json({
      message: "Password reset successfully",
      email : email.trim().toLowerCase(),
      nextStep: "login",
      instruction: "You can now login with your new password.",
      requestedId,
      duration: `${duration}ms`
    })
    try {

    } catch(error) {
      let errorMessage = "Password reset failed";
    let statusCode = 500;
    
    // Handle specific Cognito errors
    if (error.name === "CodeMismatchException") {
      errorMessage = "Invalid confirmation code";
      statusCode = 400;
      logSecurity('reset_password_invalid_code', null, requestedId, { email });
    } else if (error.name === "ExpiredCodeException") {
      errorMessage = "Confirmation code has expired. Please request a new one";
      statusCode = 400;
      logSecurity('reset_password_expired_code', null, requestedId, { email });
    } else if (error.name === "UserNotFoundException") {
      errorMessage = "User not found";
      statusCode = 404;
      logSecurity('reset_password_user_not_found', null, requestedId, { email });
    } else if (error.name === "InvalidPasswordException") {
      errorMessage = "New password does not meet requirements";
      statusCode = 400;
      logSecurity('reset_password_invalid_password_policy', null, requestedId, { email });
    } else if (error.name === "LimitExceededException") {
      errorMessage = "Too many attempts. Please try again later";
      statusCode = 429;
      logSecurity('reset_password_rate_limit', null, requestedId, { email });
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
      requestedId
    });
    }
  }
  async resendConfirmation(req, res) {
    const requestedId = req.requestId;
    const { email } = req.body;
    try {
      const startDate = Date.now()
      const result = await authService.resendConfirmation(email)
      const duration = Date.now() - startDate
      res.status(200).json({
        success: true,
        email: email,
        deliveryDetails: {
          destination: result.CodeDeliveryDetails?.Destination,
          deliveryMedium: result.CodeDeliveryDetails?.DeliveryMedium
        },
        nextStep: "confirm_email",
        message: "Confirmation code sent successfully",
        requestedId,
        duration: `${duration}ms`
      })
    } catch(error) {
      console.error('Resend confirmation error:', error);
      let errorMessage = "Failed to resend confirmation code";
      let statusCode = 500;
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
  }
  async changePassword(req,res){
    const requestedId = req.requestId
    try {
      let startDate = Date.now()
      let authHeader = req.headers['authorization']
      let accessToken = authHeader && authHeader.split(' ')[1]
      if(!accessToken){
        return res.status(400).json({
          success: false, 
          message: 'Access Token required', 
          requestedId
        })
      }
      const attr = {
        ...req.body,
        accessToken: accessToken
      }
      await  authService.changePassword(attr)
      let duration = Date.now() - startDate;
      res.status(200).json({
        message: "Password changed successfully",
        user: {
          userId: req.user.userId,
          email: req.user.email
        },
        requestedId,
        duration: `${duration}ms`
      })
    } catch(error) {
      let errorMessage = "Current password is incorrect";
      let statusCode = 400;
      if (error.name === "NotAuthorizedException") {
      errorMessage = "Current password is incorrect";
      statusCode = 400;
      
      } else if (error.name === "InvalidPasswordException") {
        errorMessage = "New password does not meet requirements";
        statusCode = 400;
        
      } else if (error.name === "LimitExceededException") {
        errorMessage = "Too many password change attempts. Please try again later";
        statusCode = 429;
        
      } else if (error.name === "InvalidParameterException") {
        errorMessage = "Invalid input parameters";
        statusCode = 400;
      }

      res.status(statusCode).json({
        error: errorMessage,
        errorType: error.name,
        requestedId
      });
    }
  }
}

module.exports = new AuthController();