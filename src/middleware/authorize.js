const { hasRole, hasPermission } = require('../policies/rbac');

/**
 * Middleware factory enforcing user role membership.
 *
 * @param {string|string[]} allowedRoles - Single role or array of authorized roles
 * @returns {Function} Express middleware function
 */
function requireRole(allowedRoles) {
  const rolesArray = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized: Authentication required'
      });
    }

    if (!hasRole(req.user.role, rolesArray)) {
      return res.status(403).json({
        error: `Forbidden: Access requires one of roles: [${rolesArray.join(', ')}]. Current role: '${req.user.role}'`
      });
    }

    next();
  };
}

/**
 * Middleware factory enforcing granular action permission.
 *
 * @param {string} permission - The permission key required (e.g. 'users:manage')
 * @returns {Function} Express middleware function
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized: Authentication required'
      });
    }

    if (!hasPermission(req.user.role, permission)) {
      return res.status(403).json({
        error: `Forbidden: Role '${req.user.role}' lacks required permission '${permission}'`
      });
    }

    next();
  };
}

module.exports = {
  requireRole,
  requirePermission
};
