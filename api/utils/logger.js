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
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: {
        service: 'ecommerce-api',
        version: '1.0.0'
    },
    transports: [
        // console transport for cloudwatch 
        new winston.transports.Console({
            handleExceptions: true,
            handleRejections: true
        })
    ],
    exitOnError: false,
})

const loggerHelper = {
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
    logAuth: (event, userId, email, requestId, success = true, error=null) => {
        logger.info('Authentication Event', {
            requestId,
            event,
            userId,
            email,
            success,
            error: error?.message || null
        })
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
    logBusiness: (event, userId, requestId, data = {}) => {
        logger.info('Business Event', {
            requestId,
            event,
            userId,
            data
        });
    },
    logError: (error, requestId, userId = null, context = {}) => {
        logger.error('Application Error', {
        requestId,
        userId,
        error: {
            name: error.name,
            message: error.message,
            stack: error.stack
        },
        context
        });
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