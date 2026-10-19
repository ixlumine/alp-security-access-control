const express = require('express');
const jwt = require('jsonwebtoken');
const { db } = require('../db/database');
const { JWT_SECRET } = require('../config/env');
const { authenticateToken } = require('../middleware/authenticate');
const { requireRole } = require('../middleware/authorize');
const { canAccessProduct } = require('../policies/abac');
const { canDeleteProduct } = require('../policies/combined');

const router = express.Router();

/**
 * Optional authentication middleware.
 * If Authorization Bearer header is present and valid, injects decoded payload into req.user.
 * Otherwise, execution continues without error.
 */
function optionalAuthenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return next();
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (!err && decoded) {
      req.user = decoded;
    }
    next();
  });
}

/**
 * GET /api/products (or /)
 * Public or authenticated list of products.
 * If unauthenticated or regular tier, VIP exclusives are marked as VIP-locked.
 */
router.get(['/', '/api/products'], optionalAuthenticate, (req, res) => {
  try {
    const isVipOrAdmin = req.user && (req.user.tier === 'vip' || req.user.role === 'admin');
    const allProducts = db.prepare('SELECT * FROM products ORDER BY id ASC').all();

    const products = allProducts.map((product) => {
      const isVip = product.is_vip_exclusive === 1;
      const isLocked = isVip && !isVipOrAdmin;

      return {
        ...product,
        is_locked: isLocked,
        vip_locked: isLocked
      };
    });

    return res.json({
      products,
      is_vip: isVipOrAdmin
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error fetching products',
      details: err.message
    });
  }
});

/**
 * GET /api/products/vip-deals (or /vip-deals)
 * Protected by authenticateToken.
 * Evaluates canAccessProduct(req.user, { is_vip_exclusive: 1 }).
 * Returns 403 Forbidden if user tier is not VIP.
 */
router.get(['/vip-deals', '/api/products/vip-deals'], authenticateToken, (req, res) => {
  try {
    const access = canAccessProduct(req.user, { is_vip_exclusive: 1 });
    if (!access.allowed) {
      return res.status(403).json({
        error: access.reason
      });
    }

    const vipProducts = db.prepare('SELECT * FROM products WHERE is_vip_exclusive = 1 ORDER BY id ASC').all();
    return res.json({
      message: 'VIP exclusive deals fetched successfully',
      products: vipProducts
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error fetching VIP deals',
      details: err.message
    });
  }
});

/**
 * GET /api/products/:id (or /:id)
 * Returns product details.
 * Evaluates canAccessProduct(req.user, product).
 * Returns 403 Forbidden if user lacks required tier for VIP products.
 */
router.get(['/:id', '/api/products/:id'], optionalAuthenticate, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({
        error: 'Invalid product ID'
      });
    }

    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
    if (!product) {
      return res.status(404).json({
        error: 'Product not found'
      });
    }

    const access = canAccessProduct(req.user, product);
    if (!access.allowed) {
      return res.status(403).json({
        error: access.reason
      });
    }

    return res.json({ product });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error fetching product',
      details: err.message
    });
  }
});

/**
 * POST /api/products (or /)
 * Protected by authenticateToken and requireRole(['admin', 'seller']).
 * Creates a new product with seller_id: req.user.id.
 */
router.post(['/', '/api/products'], authenticateToken, requireRole(['admin', 'seller']), (req, res) => {
  try {
    const { name, price, category, is_vip_exclusive = 0 } = req.body || {};

    if (!name || price === undefined || price === null || !category) {
      return res.status(400).json({
        error: 'Name, price, and category are required'
      });
    }

    const priceNum = parseInt(price, 10);
    if (isNaN(priceNum) || priceNum <= 0) {
      return res.status(400).json({
        error: 'Price must be a positive integer'
      });
    }

    const vipFlag = (is_vip_exclusive === 1 || is_vip_exclusive === true) ? 1 : 0;
    const sellerId = req.user.id;

    const insert = db.prepare(`
      INSERT INTO products (name, price, seller_id, category, is_vip_exclusive)
      VALUES (?, ?, ?, ?, ?)
    `);

    const result = insert.run(name, priceNum, sellerId, category, vipFlag);
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(result.lastInsertRowid);

    return res.status(201).json({
      message: 'Product created successfully',
      product
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error creating product',
      details: err.message
    });
  }
});

/**
 * DELETE /api/products/:id (or /:id)
 * Protected by authenticateToken.
 * Evaluates combined RBAC + ABAC policy canDeleteProduct(req.user, product, activeOrdersCount).
 * Returns 403 Forbidden with exact reason if disallowed.
 * Deletes product from DB and returns 200 OK if allowed.
 */
router.delete(['/:id', '/api/products/:id'], authenticateToken, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({
        error: 'Invalid product ID'
      });
    }

    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
    if (!product) {
      return res.status(404).json({
        error: 'Product not found'
      });
    }

    const activeOrdersRow = db.prepare(
      "SELECT COUNT(*) AS count FROM orders WHERE product_id = ? AND status IN ('pending', 'processing', 'shipped')"
    ).get(product.id);
    const activeOrdersCount = activeOrdersRow ? activeOrdersRow.count : 0;

    const decision = canDeleteProduct(req.user, product, activeOrdersCount);
    if (!decision.allowed) {
      return res.status(403).json({
        error: decision.reason
      });
    }

    db.prepare('DELETE FROM products WHERE id = ?').run(id);

    return res.status(200).json({
      message: 'Product deleted successfully',
      reason: decision.reason
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error deleting product',
      details: err.message
    });
  }
});

module.exports = router;
