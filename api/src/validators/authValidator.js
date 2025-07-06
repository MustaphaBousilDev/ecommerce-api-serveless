const {body, validationResult} = require('express-validator')

const validateRegister = [
    body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email address is required'),

    body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character'),
  
    body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),

    body('phone')
    .optional()
    .isMobilePhone()
    .withMessage('Valid phone number required'),
  
    body('address')
        .optional()
        .isLength({ max: 200 })
        .withMessage('Address must be less than 200 characters'),

    (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array(),
        requestId: req.requestId
      });
    }
    next();
  }
]
module.exports = { validateRegister };