const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const config = require('./index');

let ioInstance = null;

/**
 * Initializes Socket.io attached to the HTTP server with JWT authentication
 * and automatic room joining for users, organizations, and guardians.
 *
 * @param {import('http').Server} server
 * @returns {import('socket.io').Server}
 */
function initSocket(server) {
  const io = new Server(server, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST']
    }
  });

  // Handshake Authentication Middleware
  io.use((socket, next) => {
    const rawToken = socket.handshake.auth?.token ||
      socket.handshake.headers?.authorization;

    if (!rawToken || typeof rawToken !== 'string') {
      return next(new Error('Authentication error: Missing token'));
    }

    const token = rawToken.startsWith('Bearer ') ? rawToken.slice(7).trim() : rawToken.trim();
    if (!token) {
      return next(new Error('Authentication error: Missing token'));
    }

    try {
      const decoded = jwt.verify(token, config.JWT_SECRET || process.env.JWT_SECRET);
      socket.user = {
        id: decoded.id,
        role: decoded.role,
        organization_id: decoded.organization_id || decoded.org_id || null,
        email: decoded.email
      };
      return next();
    } catch (err) {
      return next(new Error(`Authentication error: ${err.message}`));
    }
  });

  io.on('connection', (socket) => {
    const user = socket.user;
    if (user && user.id) {
      // 1. Join user personal room
      socket.join(`user:${user.id}`);

      // 2. Join guardian personal room (receives dependent incident alerts)
      socket.join(`guardian:${user.id}`);

      // 3. Join organization room if affiliated with an organization
      if (user.organization_id) {
        socket.join(`org:${user.organization_id}`);
      }
    }

    // Support client subscription to authorized rooms
    socket.on('subscribe', ({ room, rooms } = {}) => {
      const targetRooms = rooms || (room ? [room] : []);
      for (const r of targetRooms) {
        if (typeof r === 'string') {
          if (r === `user:${user?.id}` || r === `guardian:${user?.id}`) {
            socket.join(r);
          } else if (user?.organization_id && r === `org:${user.organization_id}`) {
            socket.join(r);
          }
        }
      }
    });

    socket.on('disconnect', () => {
      // Connection cleanup handled automatically by Socket.io
    });
  });

  ioInstance = io;
  return io;
}

/**
 * Retrieves the singleton Socket.io instance.
 * @returns {import('socket.io').Server|null}
 */
function getIO() {
  return ioInstance;
}

module.exports = {
  initSocket,
  getIO
};
