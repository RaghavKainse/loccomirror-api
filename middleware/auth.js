const jwt = require('jsonwebtoken');
const User = require('../models/User');
const connectToDatabase = require('../lib/mongodb');

async function protect(req, res, next) {
  try {
    let token;

    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer ')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token || typeof token !== 'string' || token.length < 10 || token.length > 1024) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. Valid Bearer authentication token is required.',
      });
    }

    const secret = process.env.JWT_SECRET || 'loccomirror_jwt_super_secure_secret_key_2026';
    const decoded = jwt.verify(token, secret);

    await connectToDatabase();
    const user = await User.findById(decoded.id);

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'User no longer exists or has been deactivated.',
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('[Auth Middleware Error]:', error.message);
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired session token. Please log in again.',
    });
  }
}

module.exports = { protect };
