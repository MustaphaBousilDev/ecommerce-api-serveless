const winston = require('winston')

const logFormat = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({
        timestamp, level, message, ...meta
    }) => {
        return JSON.stringify({
            timestamp,
            level,
            message,
            ...meta,
            environment: process.env.NODE_ENV || 'development',
            service: 'ecommerce-api'
        })
    })
)

//create logger instance 
const logger = {
  info: (message, data) => console.log('INFO:', message, data),
  error: (message, data) => console.error('ERROR:', message, data)
};

const loggerHelpers = {
    logRequest: (req, requestId) => {
        logger.info("Incoming Request", {
            requestId,
            method: req.method,
            path: req.path,
            userAgent: req.get('User-Agent'),
            ip: req.ip,
            userId: req.user?.userId || 'anonymous'
        })
    },
    logResponse: (req,res,requestId, duration) => {
        logger.info('Request Complete', {
            requestId,
            method: req.method,
            path:req.path,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            userId: req.user?.userId || 'anonymous'
        })
    },
    logAuth: (action, userId, email, requestId, success, error = null) => {
  console.log(`[AUTH] ${action} - User: ${userId} - Email: ${email} - Success: ${success} - Request: ${requestId}`, error);
},
    logDatabase: (operation, table , userId, requestId, success = true, error = null) => {
        logger.info('Database Operation', {
            requestId,
            operation,
            table,
            userId,
            success,
            error: error?.message || null
        })
    },
    logBusiness: (action, userId, requestId, data) => {
  console.log(`[BUSINESS] ${action} - User: ${userId} - Request: ${requestId}`, data);
},
    logError: (error, requestId, userId, context) => {
  console.error(`[ERROR] ${error.message} - User: ${userId} - Request: ${requestId}`, context);
},
    logPerformance: (operation, duration, requestId, userId = null) => {
        const level = duration > 1000 ? 'warn' : 'info';
        logger.log(level, 'Performance Metric', {
            requestId,
            userId,
            operation,
            duration: `${duration}ms`,
            slow: duration > 1000
        });
    },
    logSecurity: (event, userId, requestId, details = {}) => {
        logger.warn('Security Event', {
            requestId,
            event,
            userId,
            details
        });
    }
}


module.exports = {
  logger,
  ...loggerHelpers
};