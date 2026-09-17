/**
 * Role-Based Access Control (RBAC) Middleware
 * Restricts endpoint access to specific user roles.
 *
 * @param {string[]} allowedRoles - Array of allowed roles (e.g. ['admin', 'employee'])
 */
function roleCheck(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required before checking permissions'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: `Forbidden: role '${req.user.role}' lacks sufficient permissions for this resource`
      });
    }

    return next();
  };
}

module.exports = roleCheck;
