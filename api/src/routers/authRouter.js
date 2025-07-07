const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validateRegister } = require('../validators/authValidator');

// Register endpoint
router.post('/register', validateRegister, authController.register);
router.post('/login', authController.login);
router.post('/confirm', authController.confirm);
router.post('/resend-confirmation', authController.resendConfirmation);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

module.exports = router;