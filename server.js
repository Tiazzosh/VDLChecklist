require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors({
  origin: '*'
}));

app.use(express.json());

const connectionString = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_REGISTRATION_SECRET = process.env.ADMIN_REGISTRATION_SECRET;

const pool = new Pool({
  connectionString: connectionString,
  ssl: { rejectUnauthorized: false },
});

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required.' });
  }
  next();
};

// --- USER LOGIN ---
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (isPasswordCorrect) {
      const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1d' });
      res.json({ success: true, token: token, isAdmin: user.is_admin });
    } else {
      res.status(401).json({ message: 'Invalid credentials.' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// --- PASSWORD MANAGEMENT ---
app.post('/api/user/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.userId;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  try {
    const result = await pool.query('SELECT password FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];
    if (!user) return res.sendStatus(404);

    const isPasswordCorrect = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: 'Incorrect current password.' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, userId]);
    res.json({ message: 'Password changed successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.post('/forgot-password', async (req, res) => {
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

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password.html?token=${resetToken}`;

    await transporter.sendMail({
      to: user.email,
      from: 'your-verified-sender@example.com', // Use your verified SendGrid sender email
      subject: 'Your Password Reset Request',
      text: `You requested a password reset. Click this link to reset it: ${resetUrl}`,
    });
    res.json({ message: 'If an account with that email exists, a reset link has been sent.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.post('/reset-password', async (req, res) => {
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
    res.status(500).json({ message: 'Server error.' });
  }
});

// --- ADMIN AND USER MANAGEMENT ENDPOINTS ---
// SECURE endpoint for admins to register new users
app.post('/register', authenticateToken, isAdmin, async (req, res) => {
  const { username, password, name, surname, email, job_role } = req.body;

  if (!username || !password || !name || !surname || !email || !job_role) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      'INSERT INTO users (username, password, name, surname, email, job_role, is_admin) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, username',
      [username, hashedPassword, name, surname, email, job_role, false] // New users are never admins by default
    );

    res.status(201).json({
      message: 'User registered successfully!',
      user: newUser.rows[0],
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === '23505') { // PostgreSQL unique violation error code
      return res.status(400).json({ message: 'Username or email already exists.' });
    }
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});

// Endpoint to create the VERY FIRST admin user
app.post('/register-admin', async (req, res) => {
    const { username, password, name, surname, email, job_role, secret } = req.body;

    if (secret !== ADMIN_REGISTRATION_SECRET) {
        return res.status(403).json({ message: 'Invalid secret for admin registration.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password, name, surname, email, job_role, is_admin) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [username, hashedPassword, name, surname, email, job_role, true] // Set is_admin to TRUE
        );
        res.status(201).json({ message: 'Admin user registered successfully!' });
    } catch (error) {
        console.error('Admin registration error:', error);
        res.status(500).json({ message: 'An error occurred during admin registration.' });
    }
});

// SECURE endpoint for admins to get all users
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, name, surname, email, job_role, is_admin FROM users ORDER BY id');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'An error occurred on the server.' });
    }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));