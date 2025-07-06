const {v4: uuidv4} = require('uuid')
const { 
    logger, 
    logRequest,
    logResponse, 
    logError, 
    logPerformance  
} = require('../utils/logger')

const requestLoggin = (req, res, next) => {
  req.requestId = uuidv4();
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - RequestID: ${req.requestId}`);
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
    requestLoggin,
    errorLoggin
}