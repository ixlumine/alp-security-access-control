/**
 * Role-Based Access Control (RBAC) Policy Definitions and Helpers
 */

const roles = {
  admin: [
    'admin:dashboard',
    'users:manage',
    'products:read',
    'products:create',
    'products:delete_any',
    'orders:read_all',
    'orders:refund_any'
  ],
  seller: [
    'seller:dashboard',
    'products:read',
    'products:create',
    'orders:read_store',
    'orders:refund_store'
  ],
  customer: [
    'customer:dashboard',
    'products:read',
    'orders:create',
    'orders:read_own',
    'orders:cancel_own'
  ]
};

/**
 * Check if a given role has a specific permission.
 *
 * @param {string} role - The user's role (e.g. 'admin', 'seller', 'customer')
 * @param {string} permission - The permission key to check
 * @returns {boolean} - True if granted, false otherwise
 */
function hasPermission(role, permission) {
  if (!role || !permission || !roles[role]) {
    return false;
  }
  return roles[role].includes(permission);
}

/**
 * Check if a given role is included in allowed roles.
 *
 * @param {string} role - The user's role
 * @param {string|string[]} allowedRoles - Single role or list of acceptable roles
 * @returns {boolean} - True if role matches, false otherwise
 */
function hasRole(role, allowedRoles) {
  if (!role || !allowedRoles) {
    return false;
  }
  if (Array.isArray(allowedRoles)) {
    return allowedRoles.includes(role);
  }
  if (typeof allowedRoles === 'string') {
    return allowedRoles === role;
  }
  return false;
}

module.exports = {
  roles,
  rolePermissions: roles,
  hasPermission,
  hasRole
};
