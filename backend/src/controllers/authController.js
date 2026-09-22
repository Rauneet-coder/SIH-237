const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const cryptoService = require('../services/cryptoService');
const env = require('../config/env');

/**
 * Register a new user and generate an RSA keypair
 */
async function register(req, res, next) {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required.' });
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email: email.toLowerCase() }]
    }).exec();

    if (existingUser) {
      return res.status(409).json({ error: 'A user with this username or email already exists.' });
    }

    // 1. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 2. Generate RSA-2048 keypair for recipient/sender
    const { publicKey, privateKey } = cryptoService.generateKeyPair(2048);

    // 3. Persist user with public key
    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: role || 'recipient',
      publicKey,
      isActive: true
    });

    await user.save();

    // 4. Return user profile and one-time export of private key
    return res.status(201).json({
      message: 'User registered successfully. Store your private key securely; it is never stored on the server.',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        publicKey: user.publicKey,
        createdAt: user.createdAt
      },
      privateKey
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Login user and issue JWT
 */
async function login(req, res, next) {
  try {
    const { username, email, password } = req.body;

    if ((!username && !email) || !password) {
      return res.status(400).json({ error: 'Username/email and password are required.' });
    }

    const query = username ? { username } : { email: email.toLowerCase() };
    const user = await User.findOne(query).exec();

    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid credentials or inactive account.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        role: user.role
      },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );

    return res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        publicKey: user.publicKey
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get currently authenticated user profile
 */
async function getMe(req, res, next) {
  try {
    return res.json({ user: req.user });
  } catch (error) {
    next(error);
  }
}

/**
 * Get list of active recipients with public keys for encryption distribution
 */
async function getRecipients(req, res, next) {
  try {
    const recipients = await User.find({ isActive: true })
      .select('username email role publicKey createdAt')
      .exec();

    return res.json({ recipients });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  register,
  login,
  getMe,
  getRecipients
};
