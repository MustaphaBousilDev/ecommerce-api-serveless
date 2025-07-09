

const express = require("express");
const serverless = require("serverless-http");




const app = express();

app.use(express.json());          

app.post('/auth/logout-all', ()=> {})
app.post('/auth/user-info', ()=> {})
app.post('/auth/refresh', ()=> {})
app.post('/auth/update-user-attributes', ()=> {})
app.post('/auth/verify-user-attribute', ()=> {})
app.post('/auth/delete-user', ()=> {})
app.post('/auth/resend-attribute-verification', ()=> {})
//MFA
app.post('/auth/respond-to-challenge', ()=> {})
app.post('/auth/associate-software-token', ()=> {})
app.post('/auth/verify-software-token', ()=> {})
app.post('/auth/set-user-mfa-preference', ()=> {})
//ADMIN OPERATION
app.post('/auth/admin/create-user', ()=> {})
app.post('/auth/admin/delete-user', ()=> {})
app.post('/auth/admin/disable-user', ()=> {})
app.post('/auth/admin/enable-user ', ()=> {})
app.post('/auth/auth/admin/reset-password', ()=> {})
app.post('/auth/admin/users', ()=> {})
app.post('/auth/admin/user/:userId', ()=> {})
//GROUP MANAGEMENT
app.post('/auth/admin/create-group', ()=> {})
app.post('/auth/admin/add-user-to-group', ()=> {})
app.post('/auth/admin/remove-user-from-group', ()=> {})
app.post('/auth/admin/groups', ()=> {})
app.post('/auth/admin/user-groups/:userId', ()=> {})
//Utility Endpoints
app.post('/auth/password-policy', ()=> {})
app.post('/auth/check-user-exists', ()=> {})
app.post('/aauth/user-pool-info', ()=> {})

// Your Custom Error Logging Middleware (must be before X-Ray close)
app.use(errorLoggin);

// X-Ray close segment middleware (conditional, must be last)
app.use(xrayCloseMiddleware);

// Export handler
exports.handler = serverless(app);