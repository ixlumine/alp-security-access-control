const jwt = require('jsonwebtoken');
const { JWT_SECRET, JWT_EXPIRES_IN } = require('../config/env');

/**
 * Generate a signed JWT access token for an authenticated user.
 *
 * @param {Object} user - User record from SQLite
 * @returns {string} - Signed JWT access token
 */
function generateToken(user) {
  const payload = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    tier: user.tier || 'regular',
    is_verified: user.is_verified === 1 || user.is_verified === true
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN || '2h'
  });
}

/**
 * JWT Authentication Middleware
 * Validates 'Authorization: Bearer <token>' header and injects decoded payload into req.user.
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized: Access token is missing'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        error: 'Forbidden: Invalid or expired access token'
      });
    }

    req.user = decoded;
    next();
  });
}

module.exports = {
  generateToken,
  authenticateToken
};
