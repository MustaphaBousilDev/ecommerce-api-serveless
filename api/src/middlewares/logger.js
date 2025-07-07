const {v4: uuidv4} = require('uuid')
const { 
    logger, 
    logRequest,
    logResponse, 
    logError, 
    logPerformance  
} = require('../utils/logger')

const requestLogger = (req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
};

const errorLoggin = (err, req, res, next) => {
    const requestId = req.requestId || 'unknow'
    logError(err, requestId,  req.user?.userId , {
        method: req.method,
        path: req.path, 
        body: req.body
    })

    res.status(500).json({
        error: 'Internal Server Error',
        requestId, 
        timestamp: new Date().toISOString()
    })
}


module.exports = {
    requestLogger,
    errorLoggin
}