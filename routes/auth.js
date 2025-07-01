const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const router = express.Router();

// Config
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// === ROUTES ===

// POST /login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (isPasswordCorrect) {
      const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, process.env.JWT_SECRET, { expiresIn: '1d' });
      res.json({ success: true, token: token, isAdmin: user.is_admin });
    } else {
      res.status(401).json({ message: 'Invalid credentials.' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// POST /forgot-password
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userResult.rows[0];

        if (!user) {
            return res.json({ message: 'If an account with that email exists, a reset link has been sent.' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        const tokenExpiry = new Date(Date.now() + 3600000); // 1 hour

        await pool.query('UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $3', [hashedToken, tokenExpiry, user.id]);

        const resetUrl = `${process.env.FRONTEND_URL}?token=${resetToken}`; // Changed to use query param on the main page

        await transporter.sendMail({
            to: user.email,
            from: 'your-verified-sender@example.com', // Use your verified SendGrid sender email
            subject: 'Your Password Reset Request',
            text: `You requested a password reset. Click this link to reset it: ${resetUrl}`,
        });
        res.json({ message: 'If an account with that email exists, a reset link has been sent.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

// POST /reset-password
router.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    try {
        const result = await pool.query('SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires > NOW()', [hashedToken]);
        const user = result.rows[0];
        if (!user) {
            return res.status(400).json({ message: 'Token is invalid or has expired.' });
        }
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1, password_reset_token = NULL, password_reset_expires = NULL WHERE id = $2', [hashedNewPassword, user.id]);
        res.json({ message: 'Password has been reset successfully.' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

// POST /register-admin
router.post('/register-admin', async (req, res) => {
    const { username, password, name, surname, email, job_role, secret } = req.body;
    if (secret !== process.env.ADMIN_REGISTRATION_SECRET) {
        return res.status(403).json({ message: 'Invalid secret for admin registration.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password, name, surname, email, job_role, is_admin) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [username, hashedPassword, name, surname, email, job_role, true]
        );
        res.status(201).json({ message: 'Admin user registered successfully!' });
    } catch (error) {
        console.error('Admin registration error:', error);
        res.status(500).json({ message: 'An error occurred during admin registration.' });
    }
});

module.exports = router;