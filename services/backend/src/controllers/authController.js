const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-dev-secret-key';

/**
 * Auth Controller — Handles user registration, authentication, and session retrieval.
 */
const authController = {
  /**
   * POST /api/v1/auth/signup
   */
  async signup(req, res) {
    const { email, password, full_name, role = 'individual', organization_id } = req.body;

    // Basic request shape validation
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'INVALID_EMAIL', message: 'A valid email address is required' });
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'WEAK_PASSWORD', message: 'Password must be at least 6 characters' });
    }
    if (!full_name || typeof full_name !== 'string') {
      return res.status(400).json({ error: 'INVALID_NAME', message: 'Full name is required' });
    }

    // TODO: Hash password using bcrypt, verify email uniqueness, and insert into database via User.create()
    const dummyId = 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d';
    const token = jwt.sign({ id: dummyId, email, role, organization_id: organization_id || null }, JWT_SECRET, { expiresIn: '7d' });

    return res.status(201).json({
      token,
      user: {
        id: dummyId,
        email,
        full_name,
        role,
        organization_id: organization_id || null,
        created_at: new Date().toISOString()
      }
    });
  },

  /**
   * POST /api/v1/auth/login
   */
  async login(req, res) {
    const { email, password } = req.body;

    // Basic request shape validation
    if (!email || !password) {
      return res.status(400).json({ error: 'MISSING_CREDENTIALS', message: 'Email and password are required' });
    }

    // TODO: Query User.findByEmail(email), verify password hash with bcrypt.compare(), and return 401 if invalid
    const dummyId = 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d';
    const role = email.includes('admin') ? 'admin' : 'individual';
    const organizationId = 'b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c';
    const token = jwt.sign({ id: dummyId, email, role, organization_id: organizationId }, JWT_SECRET, { expiresIn: '7d' });

    return res.status(200).json({
      token,
      user: {
        id: dummyId,
        email,
        full_name: 'Jane Doe',
        role,
        organization_id: organizationId
      }
    });
  },

  /**
   * GET /api/v1/auth/me
   */
  async getMe(req, res) {
    // TODO: Query User.findById(req.user.id) and return fresh database record
    const user = req.user || {};

    return res.status(200).json({
      id: user.id || 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d',
      email: user.email || 'analyst@enterprise.com',
      full_name: 'Jane Doe',
      role: user.role || 'admin',
      organization_id: user.organization_id || 'b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c',
      created_at: '2026-09-09T08:00:00Z'
    });
  }
};

module.exports = authController;
