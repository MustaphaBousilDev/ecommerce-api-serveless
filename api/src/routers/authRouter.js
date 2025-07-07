const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validateRegister } = require('../validators/authValidator');
// Remove this line: const { validateRegister } = require('../validators/authValidator');

router.post('/register',validateRegister, authController.register);
router.post('/login', authController.login);
router.post('/confirm', authController.confirm);

module.exports = router;