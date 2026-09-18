/**
 * Role-Based Access Control (RBAC) Middleware
 * Restricts endpoint access to specific user roles.
 * Must run after auth.js in the middleware chain (assumes req.user already exists).
 *
 * @param {string[]} allowedRoles - Array of allowed roles (e.g. ['admin'], ['individual', 'employee', 'admin'])
 * @returns {import('express').RequestHandler} Express middleware function
 */
function roleCheck(allowedRoles = []) {
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required before checking permissions'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: `Forbidden: role '${req.user.role}' lacks sufficient permissions for this resource`
      });
    }

    return next();
  };
}

module.exports = roleCheck;
