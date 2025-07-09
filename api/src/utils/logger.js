const winston = require('winston')

const customLevels = {
    levels: {
        error:0,
        warn:1,
        security:2,
        business:3,
        auth:4,
        database:5,
        performance: 6,
        info: 7,
        debug:8 
    },
    colors: {
        error: 'red',
        warn: 'yellow',
        security: 'magenta',
        business: 'green',
        auth: 'blue',
        database: 'cyan',
        performance: 'gray',
        info: 'white',
        debug: 'grey'
    }
}

const logger = winston.createLogger({
  levels: customLevels.levels,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level: level.toUpperCase(),
        message,
        ...meta
      });
    })
  ),
  defaultMeta: { 
    service: 'auth-service',
    version: '1.0.0'
  },
  transports: [
    // Console for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize({ colors: customLevels.colors }),
        winston.format.simple(),
        winston.format.printf(({ level, message, timestamp, requestId, ...meta }) => {
          const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
          return `${timestamp} [${requestId || 'NO-ID'}] ${level}: ${message} ${metaStr}`;
        })
      )
    }),
    
    // File for production
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    })
  ]
});
winston.addColors(customLevels.colors);

const logRequest = (method, path, requestId, userId = null, metadata = {}) => {
  logger.info('HTTP Request', {
    category: 'request',
    method,
    path,
    requestId,
    userId,
    ...metadata
  });
};

const logResponse = (method, path, statusCode, requestId, userId = null, metadata = {}) => {
  logger.info('HTTP Response', {
    category: 'response',
    method,
    path,
    statusCode,
    requestId,
    userId,
    ...metadata
  });
};

const logAuth = (action, userId, email, requestId, success = true, error = null) => {
  const level = success ? 'auth' : 'warn';
  logger.log(level, `Auth: ${action}`, {
    category: 'authentication',
    action,
    userId,
    email: email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : null, // Mask email
    requestId,
    success,
    error: error ? error.message : null
  });
};

const logBusiness = (action, userId, requestId, metadata = {}) => {
  logger.business(`Business: ${action}`, {
    category: 'business',
    action,
    userId,
    requestId,
    ...metadata
  });
};

const logSecurity = (event, userId, requestId, metadata = {}) => {
  logger.security(`Security Event: ${event}`, {
    category: 'security',
    event,
    userId,
    requestId,
    severity: 'high',
    ...metadata
  });
};



const logDatabase = (operation, table, userId, requestId, success = true, error = null, metadata = {}) => {
  const level = success ? 'database' : 'error';
  logger.log(level, `Database: ${operation}`, {
    category: 'database',
    operation,
    table,
    userId,
    requestId,
    success,
    error: error ? error.message : null,
    ...metadata
  });
};


const logPerformance = (operation, duration, requestId, userId = null, metadata = {}) => {
  const level = duration > 2000 ? 'warn' : 'performance';
  logger.log(level, `Performance: ${operation}`, {
    category: 'performance',
    operation,
    duration,
    requestId,
    userId,
    slow: duration > 2000,
    ...metadata
  });
};

const logError = (error, requestId, userId = null, metadata = {}) => {
  logger.error('Application Error', {
    category: 'error',
    message: error.message,
    stack: error.stack,
    name: error.name,
    requestId,
    userId,
    ...metadata
  });
};

module.exports = {
  logger,
  logRequest,
  logResponse,
  logAuth,
  logBusiness,
  logSecurity,
  logDatabase,
  logPerformance,
  logError
};