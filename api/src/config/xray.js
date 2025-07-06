let AWSXRay;
let isXRayAvailable = false;

try {
  AWSXRay = require('aws-xray-sdk-core');
  if (process.env.AWS_EXECUTION_ENV || process.env._X_AMZN_TRACE_ID) {
    AWSXRay.config([AWSXRay.plugins.ECSPlugin, AWSXRay.plugins.EC2Plugin]);
    isXRayAvailable = true;
  }
} catch (error) {
  isXRayAvailable = false;
}

const getSegment = () => {
  try {
    return isXRayAvailable ? AWSXRay.getSegment() : null;
  } catch (error) {
    return null;
  }
};

const addSubsegment = (name) => {
  try {
    const segment = getSegment();
    return segment ? segment.addNewSubsegment(name) : null;
  } catch (error) {
    return null;
  }
};

const closeSubsegment = (subsegment) => {
  try {
    if (subsegment) subsegment.close();
  } catch (error) {
    // Ignore errors when closing subsegments
  }
};

const xrayMiddleware = (req, res, next) => {
  if (isXRayAvailable && AWSXRay.express) {
    return AWSXRay.express.openSegment('ecommerce-api')(req, res, next);
  } else {
    next();
  }
};

const xrayCloseMiddleware = (req, res, next) => {
  if (isXRayAvailable && AWSXRay.express) {
    return AWSXRay.express.closeSegment()(req, res, next);
  } else {
    next();
  }
};

module.exports = {
  AWSXRay,
  isXRayAvailable,
  getSegment,
  addSubsegment,
  closeSubsegment,
  xrayMiddleware,
  xrayCloseMiddleware
};