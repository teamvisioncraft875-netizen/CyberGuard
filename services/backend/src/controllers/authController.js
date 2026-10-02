const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const Organization = require('../models/Organization');
const RefreshToken = require('../models/RefreshToken');
const auditService = require('../services/auditService');

const JWT_SECRET = config.JWT_SECRET || process.env.JWT_SECRET;
const ACCESS_TOKEN_EXPIRY = '15m'; // 15 minutes short-lived access token

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
  path: '/'
};

/**
 * Auth Controller — Handles user registration, authentication, session retrieval,
 * and dual-token refresh / logout flows.
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

      // 6. Issue short-lived access token (15m)
      const accessToken = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          organization_id: user.organization_id || null
        },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY }
      );

      // 7. Issue long-lived refresh token (7 days) and set HTTP-only cookie
      const refreshToken = await RefreshToken.create(user.id);
      res.cookie('refreshToken', refreshToken, COOKIE_OPTIONS);

      // 8. Log signup event
      auditService.log({
        organization_id: user.organization_id || null,
        user_id: user.id,
        actor_type: user.role === 'admin' ? 'admin' : 'user',
        action: auditService.AUDIT_ACTIONS.AUTH_SIGNUP,
        resource_type: 'user',
        resource_id: user.id,
        details: { email: user.email, role: user.role },
        ip_address: req.ip
      });

      // 9. Return user, accessToken, and refreshToken
      return res.status(201).json({
        token: accessToken,
        accessToken,
        refreshToken,
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
        auditService.log({
          organization_id: null,
          user_id: null,
          actor_type: 'user',
          action: auditService.AUDIT_ACTIONS.AUTH_LOGIN_FAILED,
          resource_type: 'user',
          resource_id: null,
          details: { attempted_email: normalizedEmail },
          ip_address: req.ip
        });
        return res.status(401).json({
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        });
      }

      // Compare password with bcrypt
      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) {
        auditService.log({
          organization_id: user.organization_id || null,
          user_id: user.id,
          actor_type: user.role === 'admin' ? 'admin' : 'user',
          action: auditService.AUDIT_ACTIONS.AUTH_LOGIN_FAILED,
          resource_type: 'user',
          resource_id: user.id,
          details: { attempted_email: normalizedEmail },
          ip_address: req.ip
        });
        return res.status(401).json({
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        });
      }

      // Issue short-lived access token (15m)
      const accessToken = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          organization_id: user.organization_id || null
        },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY }
      );

      // Issue long-lived refresh token (7 days) and set HTTP-only cookie
      const refreshToken = await RefreshToken.create(user.id);
      res.cookie('refreshToken', refreshToken, COOKIE_OPTIONS);

      // Log successful login
      auditService.log({
        organization_id: user.organization_id || null,
        user_id: user.id,
        actor_type: user.role === 'admin' ? 'admin' : 'user',
        action: auditService.AUDIT_ACTIONS.AUTH_LOGIN_SUCCESS,
        resource_type: 'user',
        resource_id: user.id,
        details: { email: user.email },
        ip_address: req.ip
      });

      return res.status(200).json({
        token: accessToken,
        accessToken,
        refreshToken,
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
   * POST /api/v1/auth/refresh
   * Accepts: req.body.refreshToken OR req.cookies.refreshToken
   * Generates a new access token without requiring the user to re-authenticate.
   */
  async refresh(req, res) {
    const rawToken = req.body?.refreshToken || req.cookies?.refreshToken;

    if (!rawToken || typeof rawToken !== 'string') {
      auditService.log({
        organization_id: req.user?.organization_id || null,
        user_id: req.user?.id || null,
        actor_type: req.user?.role === 'admin' ? 'admin' : 'user',
        action: auditService.AUDIT_ACTIONS.AUTH_REFRESH_FAILED,
        resource_type: 'session',
        resource_id: null,
        details: { reason: 'Missing or malformed refresh token' },
        ip_address: req.ip
      });
      return res.status(401).json({
        error: 'REFRESH_TOKEN_INVALID',
        message: 'Please login again'
      });
    }

    try {
      const tokenHash = RefreshToken.hash(rawToken);
      const userId = await RefreshToken.findValid(tokenHash, req.user?.id || null);

      if (!userId) {
        auditService.log({
          organization_id: req.user?.organization_id || null,
          user_id: req.user?.id || null,
          actor_type: req.user?.role === 'admin' ? 'admin' : 'user',
          action: auditService.AUDIT_ACTIONS.AUTH_REFRESH_FAILED,
          resource_type: 'session',
          resource_id: null,
          details: { reason: 'Refresh token not found or revoked' },
          ip_address: req.ip
        });
        return res.status(401).json({
          error: 'REFRESH_TOKEN_INVALID',
          message: 'Please login again'
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        auditService.log({
          organization_id: null,
          user_id: userId,
          actor_type: 'user',
          action: auditService.AUDIT_ACTIONS.AUTH_REFRESH_FAILED,
          resource_type: 'session',
          resource_id: null,
          details: { reason: 'Associated user record no longer exists' },
          ip_address: req.ip
        });
        return res.status(401).json({
          error: 'REFRESH_TOKEN_INVALID',
          message: 'Please login again'
        });
      }

      const accessToken = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          organization_id: user.organization_id || null
        },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY }
      );

      return res.status(200).json({
        token: accessToken,
        accessToken
      });
    } catch (err) {
      console.error('[authController.refresh Error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Token refresh failed'
      });
    }
  },

  /**
   * POST /api/v1/auth/logout
   * Requires: auth middleware
   * Revokes all refresh tokens for the authenticated user and clears the HTTP-only cookie.
   */
  async logout(req, res) {
    if (!req.user || !req.user.id) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required'
      });
    }

    try {
      await RefreshToken.revokeByUserId(req.user.id);
      res.clearCookie('refreshToken', { path: '/' });

      auditService.log({
        organization_id: req.user.organization_id || null,
        user_id: req.user.id,
        actor_type: req.user.role === 'admin' ? 'admin' : 'user',
        action: auditService.AUDIT_ACTIONS.AUTH_LOGOUT,
        resource_type: 'user',
        resource_id: req.user.id,
        details: { email: req.user.email },
        ip_address: req.ip
      });

      return res.status(200).json({
        message: 'Logged out'
      });
    } catch (err) {
      console.error('[authController.logout Error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Logout failed'
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
