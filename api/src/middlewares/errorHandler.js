const { logError } = require('../utils/logger');
const { getSegment } = require('../utils/xray');

const errorHandler = (err, req, res, next) => {
  const requestId = req.requestId || 'unknown';
  
  // Log error
  logError(err, requestId, req.user?.userId, {
    method: req.method,
    path: req.path,
    body: req.body
  });
  
  // Add error to X-Ray if available
  const segment = getSegment();
  if (segment) {
    try {
      segment.addError(err);
    } catch (e) {
      // Ignore X-Ray errors
    }
  }
  
  // Determine error response
  let statusCode = 500;
  let message = 'Internal Server Error';
  
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = err.message;
  } else if (err.name === 'UnauthorizedError') {
    statusCode = 401;
    message = 'Unauthorized';
  } else if (err.name === 'ForbiddenError') {
    statusCode = 403;
    message = 'Forbidden';
  }
  
  res.status(statusCode).json({
    success: false,
    error: message,
    requestId,
    timestamp: new Date().toISOString()
  });
};

module.exports = {
  errorHandler
};