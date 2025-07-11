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
router.post('/change_password', authController.changePassword)
router.post('/logout_all', authController.logoutAllDevices)
router.post('/refresh_token', authController.refreshToken)

router.post('/biometric/register', authController.registerBiometric);
router.post('/biometric/login', authController.loginWithBiometric);
router.get('/biometric/status', authController.getBiometricStatus);
router.delete('/biometric/delete', authController.deleteBiometric);

// Specific biometric type routes (optional - for direct access)
router.post('/biometric/face/register', async (req, res) => {
    req.body.biometricType = 'face';
    return authController.registerBiometric(req, res);
});

router.post('/biometric/face/login', async (req, res) => {
    req.body.biometricType = 'face';
    return authController.loginWithBiometric(req, res);
});

router.post('/biometric/webauthn/register', async (req, res) => {
    req.body.biometricType = 'webauthn';
    return authController.registerBiometric(req, res);
});

router.post('/biometric/webauthn/login', async (req, res) => {
    req.body.biometricType = 'webauthn';
    return authController.loginWithBiometric(req, res);
});

module.exports = router;