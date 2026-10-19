/**
 * Attribute-Based Access Control (ABAC) Policy Definitions and Helpers
 *
 * Evaluates access decisions based on subject attributes (user.tier, user.role, user.id, user.is_verified)
 * and resource attributes (product.is_vip_exclusive, order.customer_id, order.seller_id, order.status).
 */

/**
 * Evaluates whether a user is permitted to access a specific product.
 * VIP-exclusive products require the user to possess the 'vip' tier attribute.
 *
 * @param {Object} user - Decoded user payload from JWT (or null/undefined)
 * @param {Object} product - Product record containing resource attributes
 * @returns {{ allowed: boolean, reason?: string }} Decision object
 */
function canAccessProduct(user, product) {
  if (!product) {
    return { allowed: false, reason: 'Product not found' };
  }

  const isVipExclusive = product.is_vip_exclusive === 1 || product.is_vip_exclusive === true;

  if (isVipExclusive) {
    const currentTier = user && user.tier ? user.tier : 'none';
    if (!user || user.tier !== 'vip') {
      return {
        allowed: false,
        reason: "ABAC: Access denied. This product is exclusive to VIP members (Current tier: '" + currentTier + "')"
      };
    }
  }

  return { allowed: true };
}

/**
 * Evaluates whether a user is permitted to view an order.
 * Admins may view any order. Customers and sellers may only view orders where they
 * are the customer or the seller of record.
 *
 * @param {Object} user - Decoded user payload from JWT
 * @param {Object} order - Order record containing customer_id and seller_id
 * @returns {{ allowed: boolean, reason?: string }} Decision object
 */
function canViewOrder(user, order) {
  if (!user) {
    return {
      allowed: false,
      reason: 'ABAC: Access denied. You are neither the customer nor the seller of this order.'
    };
  }

  if (!order) {
    return { allowed: false, reason: 'Order not found' };
  }

  // Admin role override
  if (user.role === 'admin') {
    return { allowed: true };
  }

  // Attribute check: subject id matches customer_id OR seller_id
  if (order.customer_id === user.id || order.seller_id === user.id) {
    return { allowed: true };
  }

  return {
    allowed: false,
    reason: 'ABAC: Access denied. You are neither the customer nor the seller of this order.'
  };
}

/**
 * Evaluates whether a user is permitted to cancel an order.
 * Only the customer who placed the order may cancel it, and only when the order status is 'pending'.
 *
 * @param {Object} user - Decoded user payload from JWT
 * @param {Object} order - Order record containing customer_id and status
 * @returns {{ allowed: boolean, reason?: string }} Decision object
 */
function canCancelOrder(user, order) {
  if (!user) {
    return {
      allowed: false,
      reason: 'ABAC: Access denied. Authentication required.'
    };
  }

  if (!order) {
    return { allowed: false, reason: 'Order not found' };
  }

  // Attribute check: Subject ID must match order customer_id
  if (order.customer_id !== user.id) {
    return {
      allowed: false,
      reason: 'ABAC: Access denied. You can only cancel your own orders.'
    };
  }

  // Attribute check: Resource status must be 'pending'
  if (order.status !== 'pending') {
    return {
      allowed: false,
      reason: "ABAC: Access denied. Orders with status '" + order.status + "' cannot be cancelled (Only 'pending' allowed)."
    };
  }

  return { allowed: true };
}

module.exports = {
  canAccessProduct,
  canViewOrder,
  canCancelOrder
};
