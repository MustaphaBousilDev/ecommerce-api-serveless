const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validateRegister } = require('../validators/authValidator');

// Register endpoint
router.post('/register', validateRegister, authController.register);

module.exports = router;