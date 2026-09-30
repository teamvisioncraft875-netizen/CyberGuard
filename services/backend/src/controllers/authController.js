const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const Organization = require('../models/Organization');

const JWT_SECRET = config.JWT_SECRET || process.env.JWT_SECRET;
const TOKEN_EXPIRY = '24h';

/**
 * Auth Controller — Handles user registration, authentication, and session retrieval.
 */
const authController = {
  /**
   * POST /api/v1/auth/signup
   * Accepts: { email, password, role, organization_name }
   */
  async signup(req, res) {
    const { email, password, role, organization_name } = req.body;

    // 1. Validation
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({
        error: 'INVALID_EMAIL',
        message: 'A valid email address is required'
      });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({
        error: 'WEAK_PASSWORD',
        message: 'Password must be at least 8 characters'
      });
    }

    // Role must be 'individual' or 'employee' only (no direct admin signup)
    const effectiveRole = role || (organization_name ? 'employee' : 'individual');
    if (!['individual', 'employee'].includes(effectiveRole)) {
      return res.status(400).json({
        error: 'INVALID_ROLE',
        message: "Role must be 'individual' or 'employee'"
      });
    }

    if (effectiveRole === 'employee' && (!organization_name || typeof organization_name !== 'string' || !organization_name.trim())) {
      return res.status(400).json({
        error: 'MISSING_ORGANIZATION_NAME',
        message: 'Organization name is required for employee registration'
      });
    }

    try {
      const normalizedEmail = email.toLowerCase().trim();

      // 2. Check email uniqueness
      const existingUser = await User.findByEmail(normalizedEmail);
      if (existingUser) {
        return res.status(409).json({
          error: 'EMAIL_ALREADY_EXISTS',
          message: 'A user with this email address already exists'
        });
      }

      // 3. Organization & Role resolution
      let assignedOrgId = null;
      let finalRole = 'individual';

      if (effectiveRole === 'employee') {
        const trimmedOrgName = organization_name.trim();
        const existingOrg = await Organization.findByName(trimmedOrgName);

        if (existingOrg) {
          // Joins existing organization as employee
          assignedOrgId = existingOrg.id;
          finalRole = 'employee';
        } else {
          // First employee of a new organization creates it and becomes admin
          const newOrg = await Organization.create({ name: trimmedOrgName });
          assignedOrgId = newOrg.id;
          finalRole = 'admin';
        }
      }

      // 4. Hash password with bcrypt (cost: 10)
      const saltRounds = 10;
      const password_hash = await bcrypt.hash(password, saltRounds);

      // 5. Create user with real values in PostgreSQL
      const user = await User.create({
        email: normalizedEmail,
        password_hash,
        role: finalRole,
        organization_id: assignedOrgId
      });

      // 6. Issue real JWT with payload { id, email, role, organization_id } valid for 24h
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          organization_id: user.organization_id || null
        },
        JWT_SECRET,
        { expiresIn: TOKEN_EXPIRY }
      );

      // 7. Return user (excluding password_hash) and token
      return res.status(201).json({
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
      console.error('[authController.signup Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to create user account'
      });
    }
  },

  /**
   * POST /api/v1/auth/login
   * Accepts: { email, password }
   */
  async login(req, res) {
    const { email, password } = req.body;

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({
        error: 'MISSING_CREDENTIALS',
        message: 'Email and password are required'
      });
    }

    try {
      const normalizedEmail = email.toLowerCase().trim();
      const user = await User.findByEmail(normalizedEmail);

      // If user not found -> 401 INVALID_CREDENTIALS
      if (!user) {
        return res.status(401).json({
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        });
      }

      // Compare password with bcrypt
      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) {
        return res.status(401).json({
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        });
      }

      // Issue JWT with same payload/expiry (24h)
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          organization_id: user.organization_id || null
        },
        JWT_SECRET,
        { expiresIn: TOKEN_EXPIRY }
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
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Authentication failed'
      });
    }
  },

  /**
   * GET /api/v1/auth/me
   */
  async getMe(req, res) {
    if (!req.user || !req.user.id) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required'
      });
    }

    try {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(401).json({
          error: 'UNAUTHORIZED',
          message: 'User not found'
        });
      }

      // Exclude password_hash from response
      const { password_hash, ...safeUser } = user;
      return res.status(200).json(safeUser);
    } catch (err) {
      console.error('[authController.getMe Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve user profile'
      });
    }
  }
};

module.exports = authController;
