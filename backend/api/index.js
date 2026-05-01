const app = require('../server');

// Vercel serverless handler with explicit OPTIONS support
module.exports = (req, res) => {
  // Handle CORS preflight immediately
  res.setHeader('Access-Control-Allow-Origin', 'https://osaid56.github.io');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  return app(req, res);
};
