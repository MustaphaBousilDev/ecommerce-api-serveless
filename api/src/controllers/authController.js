const { error } = require('winston');
const authService = require('../services/authService');
const { logBusiness, logAuth, logError, logSecurity, logPerformance, logInfo } = require('../utils/logger');
const biometricService = require('../services/biometricService');



class AuthController {
  async register(req, res) {
    const { email, password, name, phone, address } = req.body;
    const requestId = req.requestId;
    
    try {
      // Log business activity
      
      
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
    logInfo('###--- Start Login Method ---###', req.requestId, null, {}, 'Controller')
    const { email, password } = req.body;
    const requestId = req.requestId;
    
    try {
      logBusiness('login_attempt', null, requestId, { 
        email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      });
      const startTime = Date.now();
      if (!email || !password) {
        logSecurity('login_missing_credentials', null, requestId, { 
          missing: { email: !email, password: !password },
          ip: req.ip
        });
        
        return res.status(400).json({
          success: false,
          error: 'Email and password are required',
          requestId
        });
      }
      const result = await authService.loginUser({ email, password });
      const duration = Date.now() - startTime;
      logPerformance('login_operation', duration, requestId, result.user?.userId, {
        email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
        hasChallenge: !!result.challenge
      });
      if (result.challenge) {
        logAuth('login_challenge_required', null, email, requestId, true, null);
        logSecurity('login_mfa_challenge', null, requestId, { 
          challenge: result.challenge,
          email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
        });
        
        return res.status(200).json({
          success: true,
          challenge: result.challenge,
          session: result.session,
          challengeParameters: result.challengeParameters,
          message: "Additional authentication required",
          requestId,
          duration: `${duration}ms`
        });
      }
      logAuth('user_logged_in', result.user.userId, email, requestId, true);
      logBusiness('login_success', result.user.userId, requestId, { 
        email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
        tokenExpiry: result.tokens?.expiresAt
      });
      
      res.status(200).json({
        success: true,
        message: "Login successful",
        data: result,
        requestId,
        duration: `${duration}ms`
      });
      
    } catch (error) {
      logError(error, requestId, null, { 
        operation: 'login', 
        email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
    
      let statusCode = 500;
      let message = "Login failed";
      
      // 🚨 Security event logging based on error type
      if (error.name === "NotAuthorizedException") {
        statusCode = 401;
        message = "Invalid email or password";
        logSecurity('login_invalid_credentials', null, requestId, { 
          email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          attempt: 'failed_authentication'
        });
        logAuth('login_failed', null, email, requestId, false, error);
        
      } else if (error.name === "UserNotFoundException") {
        statusCode = 404;
        message = "User not found";
        logSecurity('login_user_not_found', null, requestId, { 
          email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null,
          ip: req.ip,
          severity: 'medium'
        });
      
      } else if (error.name === "UserNotConfirmedException") {
        statusCode = 400;
        message = "Account not confirmed";
        logSecurity('login_unconfirmed_user', null, requestId, { 
          email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null,
          ip: req.ip,
          action_required: 'email_confirmation'
        });
        logBusiness('login_blocked_unconfirmed', null, requestId, { 
          email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
        });
        
      } else if (error.name === "TooManyRequestsException" || error.name === "LimitExceededException") {
        statusCode = 429;
        message = "Too many login attempts. Please try again later";
        logSecurity('login_rate_limit_exceeded', null, requestId, { 
          email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null,
          ip: req.ip,
          severity: 'high',
          action_taken: 'rate_limited'
        });
        
      } else if (error.name === "PasswordResetRequiredException") {
        statusCode = 400;
        message = "Password reset required";
        logSecurity('login_password_reset_required', null, requestId, { 
          email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null,
          ip: req.ip
        });
        
      } else if (error.name === "ValidationError") {
        statusCode = 400;
        message = error.message;
        logSecurity('login_validation_error', null, requestId, { 
          error: error.message,
          ip: req.ip
        });
      }
    
      // 📤 Error response
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
     
      
      const startTime = Date.now();
      await authService.confirmUser({ email, confirmationCode });
      const duration = Date.now() - startTime;
      
      
      
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
        
      } else if (error.name === "InvalidParameterException") {
        errorMessage = "Invalid input parameters";
        statusCode = 400;
      } else if (error.name === "LimitExceededException") {
        errorMessage = "Too many password reset attempts. Please try again later";
        statusCode = 429;
        
      } else if (error.name === "NotAuthorizedException") {
        errorMessage = "User account is disabled or not confirmed";
        statusCode = 403;
       
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
    const { email, confirmationCode, newPassword } = req.body;
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
      if (!email || !confirmationCode || !newPassword) {
        return res.status(400).json({
          success: false,
          error: 'Email, confirmation code, and new password are required',
          requestedId
        });
      }
    
      const startTime = Date.now();
      const result = await authService.resetPassword(req.body);
      const duration = Date.now() - startTime;
      
      logBusiness('password_reset_completed', null, requestedId, { email });
    
      res.status(200).json({
        success: true,
        message: "Password reset successfully",
        email: email.trim().toLowerCase(),
        nextStep: "login",
        instructions: "You can now login with your new password",
        requestedId,
        duration: `${duration}ms`
      });
    } catch(error) {
      logError(error, requestedId, null, { operation: 'reset_password', email });
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
        
      } else if (error.name === "UserNotFoundException") {
        errorMessage = "User not found";
        statusCode = 404;
        
      } else if (error.name === "InvalidPasswordException") {
        errorMessage = "New password does not meet requirements";
        statusCode = 400;
      
      } else if (error.name === "LimitExceededException") {
        errorMessage = "Too many attempts. Please try again later";
        statusCode = 429;
        
      } else if (error.name === "NotAuthorizedException") {
        errorMessage = "Invalid or expired confirmation code";
        statusCode = 400;
      } else if (error.name === "InvalidParameterException") {
        errorMessage = "Invalid input parameters";
        statusCode = 400;
      }
      res.status(statusCode).json({
        success: false,
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
  async logoutAllDevices(req, res) {
    const requestedId = req.requestId;
    try {
      const startTime = Date.now()
      
      const authHeader = req.headers['authorization'];
      const accessToken = authHeader && authHeader.split(' ')[1]
      if(!accessToken){
        res.status(400).json({
          success: false,
          error: 'Access token required',
          requestedId
        })
      }
      await authService.logoutAllDevices(accessToken)
      const duration = Date.now() - startTime;
      res.status(200).json({
        success: true, 
        message: 'Logged Out from all Devices successfuly',
        requestedId,
        duration: `${duration}ms`
      })
    } catch (error) {
      let statusCode = 500;
      let message ="Logout from all devices failed";
      if (error.name === "NotAuthorizedException"){
        statusCode = 401;
        message = "Invalid or expired token";
      }
      res.status(statusCode).json({
        success: false, 
        error: message,
        errorType: error.name, 
        requestedId
      })
    }
  }
  async refreshToken(req, res) {
    const { refreshToken } = req.body
    const requestedId = req.requestId
    try {
      const startTime = Date.now()
      const result = await authService.refreshAccessToken(refreshToken)
      const duration = Date.now() - startTime;
      res.status(200).json({
        success: true, 
        message: "Tokens refreshed successfully", 
        data: result, 
        requestedId,
        duration: `${duration}ms`
      })
    } catch(error) {
        let statusCode = 500;
        let message = "Token refresh failed";
        
        if (error.name === "NotAuthorizedException") {
          statusCode = 401;
          message = "Invalid or expired refresh token";
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
  async registerBiometric(req, res) {
    const requestId = req.requestId;
    const { email, biometricType, biometricData } = req.body
    try {
      if(!email || !biometricData || !biometricType){
        return res.status(400).json({
          success: false, 
          error: 'Email, biometric type, and biometric data are required',
          requestId
        })
      }
      const supportedTypes = ['face', 'webauthn', 'fingerprint'];
      if(!supportedTypes.includes(biometricType)){
        return res.status(400).json({
          success: false, 
          error: `Unsupported biometric type. Supported: ${supportedTypes.join(', ')}`,
          requestId
        })
      }
      logBusiness('biometric_registration_request', null, requestId, { 
        email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null,
        biometricType,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      });
      let result;
      const startTime = Date.now();
      switch(biometricType){
        case 'face':
          result = await biometricService.registerFaceData(
            email, 
            biometricData.image, 
            requestId
          )
          break;
        case 'webauthn':
          result = await biometricService.registerWebAuthnCredential(
            email, 
            biometricData.credential,
            requestId
          )
          break;
        default:
          throw new Error(`${biometricType} registration not implemented yet`)
        
      }
      const duration = Date.now() - startTime;
      logPerformance('login_operation', duration, requestId, result?.user?.userId, {
        email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
        hasChallenge: !!result.challenge
      });
      return res.status(201).json({
        success: true,
        message: `${biometricType} biometric registered successfully`,
        data: result,
        requestId,
        duration: `${duration}ms`
      });

    } catch(error) {
        logError(error, requestId, null, {
          operation: 'biometric_registration',
          email: email?.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
          biometricType
        });
        let statusCode = 500;
        let message = 'Biometric registration failed';
        if (error.message.includes('No face detected') || 
          error.message.includes('Multiple faces') ||
          error.message.includes('confidence too low')) {
          statusCode = 400;
          message = error.message;
        }
        res.status(statusCode).json({
          success: false,
          error: message,
          requestId
        });
    }
    
    
    
  }
  async loginWithBiometric(req, res){
    const {email, biometricType, biometricData} = req.body
    const requestedId = req.requestId
    try {
      if(!email || !biometricData || !biometricType){
        return res.status(400).json({
          success: false, 
          error: 'Email, biometric type, and biometric data are required',
          requestedId
        })
      }
      logBusiness('biometric_login_request', null, requestedId, {
        email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
        biometricType,
        ip: req.ip
      })
      let verificationResult;
      switch(biometricType) {
        case 'face': 
          verificationResult = await biometricService.verifyFaceData(
            email, biometricData.image, 
            requestedId
          )
          break;
        case 'webauthn': 
          verificationResult = await biometricService.verifyWebAuthnCredential(
            email, 
            biometricData.assertion, 
            requestedId
          )
          break;
        default:
          throw new Error(`${biometricType} verification not implemented yet`)
      }
      if(!verificationResult.verified){
        logSecurity('biometric_login_failed', null, requestedId, {
          email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
          biometricType,
          reason: verificationResult.reason,
          confidence: verificationResult.confidence
        })
        return res.status(401).json({
          success: false, 
          error: 'Biometric verification failed',
          reason: verificationResult.reason,
          confidence: verificationResult.confidence,
          requestedId
        })
      }
      //generate cognito token for verefied user 
      const authResult = await this.generateTokensForBiometricUser(email)
      logAuth('biometric_login_success', authResult.user.userId, email, requestedId, true);
      logBusiness('biometric_login_completed', authResult.user.userId, requestedId, {
        email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
        biometricType,
        confidence: verificationResult.confidence
      });
      res.status(200).json({
        success: true,
        message: 'Biometric login successful',
        data: {
            user: authResult.user,
            tokens: authResult.tokens,
            biometric: {
                type: biometricType,
                confidence: verificationResult.confidence,
                verified: true
            }
        },
        requestedId
      });
    } catch(error) {
        logError(error, requestedId, null, {
          operation: 'biometric_login',
          email: email?.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
          biometricType
        });

        let statusCode = 500;
        let message = 'Biometric login failed';
        if (error.message.includes('No face data registered') ||
          error.message.includes('No WebAuthn credential registered')) {
          statusCode = 404;
          message = 'No biometric data registered for this user';
        }

        res.status(statusCode).json({
            success: false,
            error: message,
            requestedId
        });
    }
  }
  async generateTokensForBiometricUser(email) {
    try {
        const result = await authService.loginUserForBiometric(email);
        return result;
        
    } catch (error) {
        // Option 2: Admin authentication (requires admin privileges)
        const adminResult = await cognitoService.adminAuthenticateUser(email);
        return this.processCognitoTokens(adminResult);
    }
  }
  async getBiometricStatus(req, res) {
    const { email } = req.query;
    const requestId = req.requestId;

    try {
        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email is required',
                requestId
            });
        }

        const biometrics = await biometricService.getUserBiometrics(email);
        
        const status = {
            hasAny: biometrics.length > 0,
            types: biometrics.map(b => ({
                type: b.biometricType,
                registeredAt: b.createdAt,
                lastUpdated: b.updatedAt
            }))
        };

        res.status(200).json({
            success: true,
            data: status,
            requestId
        });

    } catch (error) {
        logError(error, requestId, null, {
            operation: 'get_biometric_status',
            email: email?.replace(/(.{2})(.*)(@.*)/, '$1***$3')
        });

        res.status(500).json({
            success: false,
            error: 'Failed to get biometric status',
            requestId
        });
    }
  }
  async deleteBiometric(req, res) {
    const { email, biometricType } = req.body;
    const requestId = req.requestId;

    try {
        if (!email || !biometricType) {
            return res.status(400).json({
                success: false,
                error: 'Email and biometric type are required',
                requestId
            });
        }

        await biometricService.deleteBiometricData(email, biometricType);

        logBusiness('biometric_deleted', null, requestId, {
            email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
            biometricType
        });

        res.status(200).json({
            success: true,
            message: `${biometricType} biometric data deleted successfully`,
            requestId
        });

    } catch (error) {
        logError(error, requestId, null, {
            operation: 'delete_biometric',
            email: email?.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
            biometricType
        });

        res.status(500).json({
            success: false,
            error: 'Failed to delete biometric data',
            requestId
        });
    }
  }
  processCognitoTokens(cognitoResult) {
    const tokens = cognitoResult.AuthenticationResult;
    const userInfo = this.extractUserInfo(tokens.IdToken);
    
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
  }
  extractUserInfo(idToken) {
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

module.exports = new AuthController();