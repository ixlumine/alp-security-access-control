const express = require('express');
const { db } = require('../db/database');
const { authenticateToken } = require('../middleware/authenticate');
const { requireRole, requirePermission } = require('../middleware/authorize');

const router = express.Router();

// Enforce authentication on all admin endpoints
router.use(authenticateToken);

/**
 * GET /api/admin/metrics (or /metrics)
 * Protected by requireRole(['admin']).
 * Returns platform metrics: total users, total products, total revenue.
 */
router.get(['/metrics', '/api/admin/metrics'], requireRole(['admin']), (req, res) => {
  try {
    const userRow = db.prepare('SELECT COUNT(*) as count FROM users').get();
    const productRow = db.prepare('SELECT COUNT(*) as count FROM products').get();
    const revenueRow = db.prepare(`
      SELECT COALESCE(SUM(amount), 0) as total
      FROM orders
      WHERE status NOT IN ('cancelled', 'refunded')
    `).get();

    const totalUsers = userRow ? userRow.count : 0;
    const totalProducts = productRow ? productRow.count : 0;
    const totalRevenue = revenueRow ? revenueRow.total : 0;

    return res.json({
      metrics: {
        totalUsers,
        totalProducts,
        totalRevenue
      },
      totalUsers,
      totalProducts,
      totalRevenue,
      total_users: totalUsers,
      total_products: totalProducts,
      total_revenue: totalRevenue
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error fetching admin metrics',
      details: err.message
    });
  }
});

/**
 * GET /api/admin/users (or /users)
 * Protected by requirePermission('users:manage').
 * Returns sanitized list of users from database.
 */
router.get(['/users', '/api/admin/users'], requirePermission('users:manage'), (req, res) => {
  try {
    const users = db.prepare(`
      SELECT id, username, email, role, tier, is_verified, created_at
      FROM users
      ORDER BY id ASC
    `).all();

    return res.json({ users });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error fetching users list',
      details: err.message
    });
  }
});

module.exports = router;
