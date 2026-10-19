const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });

module.exports = {
  PORT: process.env.PORT || 4000,
  JWT_SECRET: process.env.JWT_SECRET || 'fallback-secret-alp-cybersecurity',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '2h',
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || 'dummy-client-id',
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || 'dummy-client-secret',
  CALLBACK_URL: process.env.CALLBACK_URL || 'http://localhost:4000/auth/google/callback'
};
