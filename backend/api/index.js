const app = require('../server');

// Allowed origins for CORS
const ALLOWED_ORIGINS = [
  'https://osaid56.github.io',
  'https://aibyosaid.vercel.app',
];

// Vercel serverless handler with explicit OPTIONS support
module.exports = (req, res) => {
  const origin = req.headers.origin;
  // Set correct origin header (must match the requesting origin exactly)
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGINS[0]);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  return app(req, res);
};
