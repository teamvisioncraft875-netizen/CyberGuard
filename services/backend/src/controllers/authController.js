const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const Organization = require('../models/Organization');

const JWT_SECRET = config.JWT_SECRET || process.env.JWT_SECRET || 'cyberguard-dev-secret-key';

/**
 * Auth Controller — Handles user registration, authentication, and session retrieval.
 */
const authController = {
  /**
   * POST /api/v1/auth/signup
   */
  async signup(req, res) {
    const { email, password, full_name, organization_name, organization_id, role } = req.body;

    // Basic request shape validation
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'INVALID_EMAIL', message: 'A valid email address is required' });
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'WEAK_PASSWORD', message: 'Password must be at least 6 characters' });
    }

    try {
      const normalizedEmail = email.toLowerCase().trim();

      // Verify email uniqueness
      const existingUser = await User.findByEmail(normalizedEmail);
      if (existingUser) {
        return res.status(409).json({ error: 'EMAIL_ALREADY_EXISTS', message: 'A user with this email address already exists' });
      }

      // Determine organization and role:
      // If signup includes an organization_name that doesn't exist yet, create the organization and make that user its admin.
      // If they join an existing organization_name, they become an employee.
      let assignedOrgId = organization_id || null;
      let assignedRole = role || 'individual';

      if (organization_name && typeof organization_name === 'string' && organization_name.trim().length > 0) {
        const orgName = organization_name.trim();
        let org = await Organization.findByName(orgName);
        if (!org) {
          org = await Organization.create({ name: orgName });
          assignedOrgId = org.id;
          assignedRole = 'admin';
        } else {
          assignedOrgId = org.id;
          assignedRole = 'employee';
        }
      } else if (assignedOrgId) {
        assignedRole = role === 'admin' ? 'admin' : 'employee';
      }

      // Hash password using bcrypt
      const saltRounds = 10;
      const password_hash = await bcrypt.hash(password, saltRounds);

      // Insert into users table via User.create()
      const user = await User.create({
        email: normalizedEmail,
        password_hash,
        role: assignedRole,
        organization_id: assignedOrgId
      });

      // Issue real JWT
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          organization_id: user.organization_id || null
        },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      const userResponse = {
        id: user.id,
        email: user.email,
        role: user.role,
        organization_id: user.organization_id || null,
        created_at: user.created_at
      };

      if (full_name && typeof full_name === 'string') {
        userResponse.full_name = full_name;
      }

      return res.status(201).json({
        token,
        user: userResponse
      });
    } catch (err) {
      console.error('[authController.signup Error]', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: 'Failed to create user account' });
    }
  },

  /**
   * POST /api/v1/auth/login
   */
  async login(req, res) {
    const { email, password } = req.body;

    // Basic request shape validation
    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'MISSING_CREDENTIALS', message: 'Email and password are required' });
    }

    try {
      const normalizedEmail = email.toLowerCase().trim();
      const user = await User.findByEmail(normalizedEmail);
      if (!user) {
        return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });
      }

      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) {
        return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });
      }

      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          organization_id: user.organization_id || null
        },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.status(200).json({
        token,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          organization_id: user.organization_id || null,
          created_at: user.created_at
        }
      });
    } catch (err) {
      console.error('[authController.login Error]', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: 'Authentication failed' });
    }
  },

  /**
   * GET /api/v1/auth/me
   */
  async getMe(req, res) {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required' });
    }

    try {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User record not found' });
      }

      const { password_hash, ...safeUser } = user;
      return res.status(200).json(safeUser);
    } catch (err) {
      console.error('[authController.getMe Error]', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: 'Failed to retrieve user profile' });
    }
  }
};

module.exports = authController;
