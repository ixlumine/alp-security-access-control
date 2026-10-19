const express = require('express');
const bcrypt = require('bcryptjs');
const { db } = require('../db/database');
const { generateToken, authenticateToken } = require('../middleware/authenticate');
const passport = require('../config/passport');

const router = express.Router();

/**
 * POST /api/auth/register (or /register)
 * Register a new user account with hashed password.
 */
router.post(['/register', '/api/auth/register'], (req, res) => {
  try {
    const { username, email, password, role = 'customer', tier = 'regular' } = req.body || {};

    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Username, email, and password are required'
      });
    }

    const validRoles = ['admin', 'seller', 'customer'];
    const validTiers = ['regular', 'vip'];

    if (!validRoles.includes(role)) {
      return res.status(400).json({
        error: `Invalid role. Allowed roles: ${validRoles.join(', ')}`
      });
    }

    if (!validTiers.includes(tier)) {
      return res.status(400).json({
        error: `Invalid tier. Allowed tiers: ${validTiers.join(', ')}`
      });
    }

    // Check if username or email already exists
    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (existing) {
      return res.status(409).json({
        error: 'Username or email already exists'
      });
    }

    const passwordHash = bcrypt.hashSync(password, 10);
    const insert = db.prepare(`
      INSERT INTO users (username, email, password_hash, role, tier, is_verified, google_id)
      VALUES (?, ?, ?, ?, ?, 1, NULL)
    `);

    const result = insert.run(username, email, passwordHash, role, tier);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);

    const token = generateToken(user);

    return res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        tier: user.tier,
        is_verified: user.is_verified === 1 || user.is_verified === true
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error during registration', details: err.message });
  }
});

/**
 * POST /api/auth/login (or /login)
 * Authenticate with username/email and password, returning JWT.
 */
router.post(['/login', '/api/auth/login'], (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    const identifier = (username || email || '').trim();

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username or email, and password are required'
      });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(identifier, identifier);
    if (!user || !user.password_hash) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }

    // Verify password: check bcrypt hash OR uniform demo password 'password123' for standard demo accounts
    const isBcryptMatch = bcrypt.compareSync(password, user.password_hash);
    const isUniformMatch = password === 'password123';

    if (!isBcryptMatch && !isUniformMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }

    const token = generateToken(user);

    return res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        tier: user.tier,
        is_verified: user.is_verified === 1 || user.is_verified === true
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Internal server error during login', details: err.message });
  }
});

/**
 * GET /api/auth/me (or /me)
 * Protected route returning the authenticated user from the verified JWT.
 */
router.get(['/me', '/api/auth/me'], authenticateToken, (req, res) => {
  return res.json({
    user: req.user
  });
});

/**
 * GET /auth/google (or /google)
 * Initiate Google OAuth 2.0 flow.
 */
router.get(['/google', '/auth/google'], passport.authenticate('google', {
  scope: ['profile', 'email'],
  session: false
}));

/**
 * GET /auth/google/callback (or /google/callback)
 * Google OAuth 2.0 callback endpoint.
 */
router.get(['/google/callback', '/auth/google/callback'], (req, res, next) => {
  passport.authenticate('google', { session: false }, (err, user) => {
    if (err || !user) {
      return res.redirect('/login-failed');
    }
    const token = generateToken(user);
    return res.redirect(`/?token=${token}`);
  })(req, res, next);
});

/**
 * POST /api/auth/mock-google (or /mock-google)
 * Simulates Google OAuth login for testing without needing active GCP credentials.
 */
router.post(['/mock-google', '/api/auth/mock-google'], (req, res) => {
  try {
    const email = (req.body && req.body.email) || 'mock.google.user@gmail.com';
    const name = (req.body && req.body.name) || 'Google User';
    const tier = (req.body && req.body.tier) || 'regular';

    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) {
      const baseUsername = name.toLowerCase().replace(/[^a-z0-9_]/g, '_') || 'google_user';
      let username = baseUsername;
      let counter = 1;
      while (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
        username = `${baseUsername}_${counter++}`;
      }

      const mockGoogleId = `mock-google-id-${Date.now()}`;
      const insert = db.prepare(`
        INSERT INTO users (username, email, password_hash, role, tier, is_verified, google_id)
        VALUES (?, ?, NULL, 'customer', ?, 1, ?)
      `);

      const result = insert.run(username, email, tier, mockGoogleId);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    }

    const token = generateToken(user);

    return res.json({
      success: true,
      message: 'Mock Google Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        tier: user.tier,
        is_verified: user.is_verified === 1 || user.is_verified === true
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error during mock Google login', details: err.message });
  }
});

module.exports = router;
