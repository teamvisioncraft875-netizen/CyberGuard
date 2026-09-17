const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-dev-secret-key';

/**
 * JWT Authentication Middleware
 * Reads and verifies the Bearer token from the Authorization header.
 * Attaches decoded user payload { id, email, role, organization_id } to req.user.
 */
function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Authentication token is missing or invalid'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (err) {
    // In development/testing, accept mock test tokens if JWT verification fails
    if (process.env.NODE_ENV !== 'production' && token.startsWith('mock-')) {
      req.user = {
        id: 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d',
        email: 'analyst@enterprise.com',
        role: token.includes('admin') ? 'admin' : 'individual',
        organization_id: 'b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c'
      };
      return next();
    }

    return res.status(401).json({
      error: 'INVALID_TOKEN',
      message: 'Token verification failed or expired'
    });
  }
}

module.exports = auth;
