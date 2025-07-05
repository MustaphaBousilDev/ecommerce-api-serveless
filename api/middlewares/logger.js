const {v4: uuidv4} = require('uuid')
const { 
    logger, 
    logRequest,
    logResponse, 
    logError, 
    logPerformance  
} = require('../utils/logger')

const requestLoggin = (req, res, next) => {
    const startTime = Date.now()
    const requestId = uuidv4()

    req.requestId = requestId
    req.startTime = startTime

    logRequest(req, requestId)

    //ovveride res.json to log response
    const originalJSON = res.json;
    res.json = function(body){
        const duration = Date.now() - startTime;
        logResponse(req, res, requestId, duration)
        if (duration > 500) {  
           logPerformance(`${req.method} ${req.path} `, duration, requestId, req.user?.userId)
        }
        return originalJSON.call(this, body)
    }

    res.on('finish', ()=>{
        if (res.statusCode >= 400) {
            logError(new Error(`HTTP ${res.statusCode}`), requestId, req.user?.userId, {
                method: req.method,
                path: req.path, 
                statusCode: res.statusCode
            })
        }
    })
    next()
}

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