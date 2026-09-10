const express = require('express');
const router = express.Router();
const User = require('../models/User');
const connectToDatabase = require('../lib/mongodb');
const { protect } = require('../middleware/auth');
const { validateEmail, validatePassword, validateName, sanitizeString } = require('../lib/security');

/**
 * @route   POST /api/auth/signup
 * @desc    Register a new user account with secure validation
 * @access  Public
 */
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Strict input validations
    const nameVal = validateName(name);
    if (!nameVal.valid) {
      return res.status(400).json({ success: false, message: nameVal.message });
    }

    const emailVal = validateEmail(email);
    if (!emailVal.valid) {
      return res.status(400).json({ success: false, message: emailVal.message });
    }

    const passwordVal = validatePassword(password);
    if (!passwordVal.valid) {
      return res.status(400).json({ success: false, message: passwordVal.message });
    }

    await connectToDatabase();

    const normalizedEmail = emailVal.value;
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email address already exists. Please log in instead.',
      });
    }

    const user = await User.create({
      name: nameVal.value,
      email: normalizedEmail,
      password: passwordVal.value,
      avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(normalizedEmail)}`,
      plan: 'free',
    });

    const token = user.generateAuthToken();

    return res.status(201).json({
      success: true,
      message: 'Account created successfully! Welcome to loccoMirror.',
      token,
      user,
    });
  } catch (error) {
    console.error('[Signup Error]:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to create account at this time. Please try again.',
    });
  }
});

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user and return JWT token
 * @access  Public
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const emailVal = validateEmail(email);
    if (!emailVal.valid) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }

    if (!password || typeof password !== 'string') {
      return res.status(400).json({ success: false, message: 'Please provide your password.' });
    }

    await connectToDatabase();

    const normalizedEmail = emailVal.value;
    // Explicitly query password which is excluded in schema by default
    const user = await User.findOne({ email: normalizedEmail }).select('+password');

    if (!user) {
      // Return identical error message to prevent user enumeration attacks
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password. Please check your credentials.',
      });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password. Please check your credentials.',
      });
    }

    user.lastLogin = Date.now();
    await user.save();

    const token = user.generateAuthToken();

    return res.status(200).json({
      success: true,
      message: 'Logged in successfully!',
      token,
      user,
    });
  } catch (error) {
    console.error('[Login Error]:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to sign in at this time. Please check your internet connection.',
    });
  }
});

/**
 * @route   GET /api/auth/me
 * @desc    Get currently authenticated user's profile
 * @access  Private (Requires Bearer token)
 */
router.get('/me', protect, async (req, res) => {
  try {
    return res.status(200).json({
      success: true,
      user: req.user,
    });
  } catch (error) {
    console.error('[Get Profile Error]:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve profile data.',
    });
  }
});

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile (Name / Avatar)
 * @access  Private (Requires Bearer token)
 */
router.put('/profile', protect, async (req, res) => {
  try {
    const { name, avatar } = req.body;
    const user = req.user;

    if (name) {
      const nameVal = validateName(name);
      if (!nameVal.valid) {
        return res.status(400).json({ success: false, message: nameVal.message });
      }
      user.name = nameVal.value;
    }

    if (avatar && typeof avatar === 'string') {
      user.avatar = sanitizeString(avatar, 500);
    }

    await user.save();

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully!',
      user,
    });
  } catch (error) {
    console.error('[Update Profile Error]:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to update profile.',
    });
  }
});

/**
 * @route   GET /api/auth/health
 * @desc    Healthcheck status indicator
 * @access  Public
 */
router.get('/health', (req, res) => {
  res.status(200).json({
    status: 'online',
    service: 'loccoMirror Secure Auth Gateway',
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
