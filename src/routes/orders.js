const express = require('express');
const { db } = require('../db/database');
const { authenticateToken } = require('../middleware/authenticate');
const { canViewOrder, canCancelOrder, canAccessProduct } = require('../policies/abac');
const { canApproveRefund } = require('../policies/combined');

const router = express.Router();

// Enforce authentication on all order operations
router.use(authenticateToken);

/**
 * GET /api/orders (or /)
 * Returns order listings filtered by authenticated user's role:
 * - Admin: all orders
 * - Seller: orders for their seller account (seller_id = req.user.id)
 * - Customer: orders placed by their customer account (customer_id = req.user.id)
 */
router.get(['/', '/api/orders'], (req, res) => {
  try {
    let orders;
    if (req.user.role === 'admin') {
      orders = db.prepare('SELECT * FROM orders ORDER BY id DESC').all();
    } else if (req.user.role === 'seller') {
      orders = db.prepare('SELECT * FROM orders WHERE seller_id = ? ORDER BY id DESC').all(req.user.id);
    } else {
      orders = db.prepare('SELECT * FROM orders WHERE customer_id = ? ORDER BY id DESC').all(req.user.id);
    }

    return res.json({ orders });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error fetching orders',
      details: err.message
    });
  }
});

/**
 * GET /api/orders/:id (or /:id)
 * Returns a single order by ID after evaluating ABAC viewing policies.
 * Evaluates canViewOrder(req.user, order).
 * Returns 403 Forbidden if user is neither admin, order customer, nor order seller.
 */
router.get(['/:id', '/api/orders/:id'], (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({
        error: 'Invalid order ID'
      });
    }

    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    const access = canViewOrder(req.user, order);
    if (!access.allowed) {
      return res.status(403).json({
        error: access.reason
      });
    }

    return res.json({ order });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error fetching order',
      details: err.message
    });
  }
});

/**
 * POST /api/orders (or /)
 * Creates a new order for the authenticated user (customer).
 */
router.post(['/', '/api/orders'], (req, res) => {
  try {
    const { product_id, amount } = req.body || {};

    if (!product_id) {
      return res.status(400).json({
        error: 'product_id is required'
      });
    }

    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
    if (!product) {
      return res.status(404).json({
        error: 'Product not found'
      });
    }

    // Evaluate ABAC product eligibility before permitting order placement
    const access = canAccessProduct(req.user, product);
    if (!access.allowed) {
      return res.status(403).json({
        error: access.reason
      });
    }

    const orderAmount = (amount !== undefined && amount !== null) ? parseInt(amount, 10) : product.price;
    const customerId = req.user.id;
    const sellerId = product.seller_id;

    const insert = db.prepare(`
      INSERT INTO orders (customer_id, seller_id, product_id, amount, status, refund_reason)
      VALUES (?, ?, ?, ?, 'pending', NULL)
    `);

    const result = insert.run(customerId, sellerId, product.id, orderAmount);
    const newOrder = db.prepare('SELECT * FROM orders WHERE id = ?').get(result.lastInsertRowid);

    return res.status(201).json({
      message: 'Order created successfully',
      order: newOrder
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error creating order',
      details: err.message
    });
  }
});

/**
 * POST /api/orders/:id/cancel (or /:id/cancel)
 * Evaluates ABAC cancellation policies:
 * - Customer must own the order (order.customer_id === req.user.id)
 * - Order status must be 'pending'
 * Updates order status to 'cancelled' upon authorization.
 */
router.post(['/:id/cancel', '/api/orders/:id/cancel'], (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({
        error: 'Invalid order ID'
      });
    }

    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    const access = canCancelOrder(req.user, order);
    if (!access.allowed) {
      return res.status(403).json({
        error: access.reason
      });
    }

    db.prepare("UPDATE orders SET status = 'cancelled' WHERE id = ?").run(id);
    const updatedOrder = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);

    return res.json({
      message: 'Order cancelled successfully',
      order: updatedOrder
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error cancelling order',
      details: err.message
    });
  }
});

/**
 * POST /api/orders/:id/approve-refund (or /:id/approve-refund)
 * Evaluates combined RBAC + ABAC refund approval policies:
 * - Admin: can approve refunds of any amount
 * - Seller: can approve refunds only if they own the store (seller_id === user.id)
 *   AND amount <= Rp 500.000 AND status === 'refund_requested'
 * Updates order status to 'refunded' upon authorization.
 */
router.post(['/:id/approve-refund', '/api/orders/:id/approve-refund'], (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({
        error: 'Invalid order ID'
      });
    }

    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    const decision = canApproveRefund(req.user, order);
    if (!decision.allowed) {
      return res.status(403).json({
        error: decision.reason
      });
    }

    db.prepare("UPDATE orders SET status = 'refunded' WHERE id = ?").run(id);

    return res.status(200).json({
      message: 'Refund approved successfully',
      reason: decision.reason
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error approving refund',
      details: err.message
    });
  }
});

/**
 * POST /api/orders/:id/request-refund (or /:id/request-refund)
 * Allows customer to request a refund on their order.
 */
router.post(['/:id/request-refund', '/api/orders/:id/request-refund'], (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: 'Invalid order ID' });
    }

    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (order.customer_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'ABAC: Hanya pemilik pesanan yang dapat mengajukan refund' });
    }

    if (order.status === 'cancelled' || order.status === 'refunded') {
      return res.status(400).json({ error: `Pesanan dengan status '${order.status}' tidak dapat diajukan refund` });
    }

    db.prepare("UPDATE orders SET status = 'refund_requested', refund_reason = ? WHERE id = ?").run(
      req.body && req.body.reason ? req.body.reason : 'Barang rusak / minta pengembalian dana',
      id
    );

    return res.status(200).json({
      message: 'Permintaan refund berhasil dikirim',
      order: db.prepare('SELECT * FROM orders WHERE id = ?').get(id)
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Internal server error requesting refund',
      details: err.message
    });
  }
});

module.exports = router;
