const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validateRegister } = require('../validators/authValidator');
// Remove this line: const { validateRegister } = require('../validators/authValidator');

router.post('/register',/**validateRegister (for using +009 method ) in production remove it */ authController.register);
router.post('/login', authController.login);
router.post('/confirm', authController.confirm);
router.post('/logout', authController.logout)
router.post('/resend_confirmation', authController.resendConfirmation)
router.post('/forgot_password', authController.forgotPassword)
router.post('/reset_password', authController.resetPassword)

module.exports = router;