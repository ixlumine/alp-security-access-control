/**
 * Combined RBAC + ABAC Policy Definitions and Helpers (Compound Decisions)
 *
 * Evaluates decisions requiring both Subject Role (RBAC) and dynamic
 * Resource / Environmental Attributes (ABAC).
 */

/**
 * Evaluates whether a user is permitted to delete a product.
 * Compound Rules:
 * 1. RBAC: Admins have global deletion privileges regardless of ownership or orders.
 *    Non-admin, non-sellers are rejected immediately.
 * 2. ABAC: Sellers must own the product (product.seller_id === user.id).
 * 3. ABAC: The product must not have active orders (activeOrdersCount === 0).
 *
 * @param {Object} user - Decoded user payload from JWT
 * @param {Object} product - Product record from database
 * @param {number} activeOrdersCount - Number of active orders ('pending', 'processing', 'shipped')
 * @returns {{ allowed: boolean, reason: string }} Decision object
 */
function canDeleteProduct(user, product, activeOrdersCount = 0) {
  if (!user) {
    return {
      allowed: false,
      reason: 'Authentication required'
    };
  }

  // 1. RBAC check
  if (user.role === 'admin') {
    return {
      allowed: true,
      reason: 'RBAC: Admin granted global deletion rights'
    };
  }

  if (user.role !== 'seller') {
    return {
      allowed: false,
      reason: "RBAC: Only 'admin' or 'seller' can delete products. Role '" + user.role + "' lacks delete authority."
    };
  }

  if (!product) {
    return {
      allowed: false,
      reason: 'Product not found'
    };
  }

  // 2. ABAC Attribute: Ownership check
  if (product.seller_id !== user.id) {
    return {
      allowed: false,
      reason: "ABAC: Ownership mismatch. You (ID: " + user.id + ") are not the seller of product ID " + product.id + " (Seller ID: " + product.seller_id + ")"
    };
  }

  // 3. ABAC Attribute: Active Orders constraint check
  if (activeOrdersCount > 0) {
    return {
      allowed: false,
      reason: "ABAC: Integrity constraint. Product has " + activeOrdersCount + " active order(s) and cannot be deleted."
    };
  }

  return {
    allowed: true,
    reason: 'RBAC+ABAC: Seller owns product and no active orders exist'
  };
}

/**
 * Evaluates whether a user is permitted to approve a refund for an order.
 * Compound Rules:
 * 1. RBAC: Admins can approve refunds of any amount.
 *    Non-admin, non-sellers cannot approve refunds.
 * 2. ABAC: Sellers must own the store associated with the order (order.seller_id === user.id).
 * 3. ABAC: The refund amount must not exceed the seller approval limit (Rp 500.000).
 * 4. ABAC: The order must be in 'refund_requested' status.
 *
 * @param {Object} user - Decoded user payload from JWT
 * @param {Object} order - Order record from database
 * @returns {{ allowed: boolean, reason: string }} Decision object
 */
function canApproveRefund(user, order) {
  if (!user) {
    return {
      allowed: false,
      reason: 'Authentication required'
    };
  }

  // 1. RBAC check
  if (user.role === 'admin') {
    return {
      allowed: true,
      reason: 'RBAC: Admin can approve refunds of any amount'
    };
  }

  if (user.role !== 'seller') {
    return {
      allowed: false,
      reason: "RBAC: Only 'admin' or 'seller' can approve refunds. Role '" + user.role + "' cannot approve refunds."
    };
  }

  if (!order) {
    return {
      allowed: false,
      reason: 'Order not found'
    };
  }

  // 2. ABAC Attribute: Store ownership check
  if (order.seller_id !== user.id) {
    return {
      allowed: false,
      reason: "ABAC: Order store mismatch. Order belongs to store ID " + order.seller_id + ", not your store ID " + user.id + "."
    };
  }

  // 3. ABAC Attribute: Amount limit check (Limit: Rp 500.000)
  if (order.amount > 500000) {
    return {
      allowed: false,
      reason: "ABAC: Amount threshold exceeded. Refund amount Rp " + order.amount.toLocaleString() + " exceeds seller approval ceiling of Rp 500,000. Admin approval required."
    };
  }

  // 4. ABAC Attribute: Lifecycle status check
  if (order.status !== 'refund_requested') {
    return {
      allowed: false,
      reason: "ABAC: Invalid state. Order status is '" + order.status + "', must be 'refund_requested' to approve refund."
    };
  }

  return {
    allowed: true,
    reason: 'RBAC+ABAC: Seller owns order and amount is within Rp 500,000 threshold'
  };
}

module.exports = {
  canDeleteProduct,
  canApproveRefund
};
