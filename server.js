require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// Initial Application Setup
const app = express();
app.use(cors());
app.use(express.json());

// Database and Secrets from Environment Variables
const connectionString = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_REGISTRATION_SECRET = process.env.ADMIN_REGISTRATION_SECRET; // For creating the first admin

const pool = new Pool({
  connectionString: connectionString,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Middleware to authenticate JWT and find user
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401); // No token

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token
    req.user = user;
    next();
  });
};

// Middleware to check if user is an admin
const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required.' });
  }
  next();
};

// --- API Endpoints ---

// User Login Endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (isPasswordCorrect) {
            // Create a token containing the user's role
            const token = jwt.sign(
                { userId: user.id, username: user.username, isAdmin: user.is_admin },
                JWT_SECRET,
                { expiresIn: '1d' }
            );
            // Send back the user's admin status to the frontend
            res.json({
                success: true,
                message: 'Login successful!',
                token: token,
                isAdmin: user.is_admin
            });
        } else {
            res.status(401).json({ message: 'Invalid credentials.' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An error occurred on the server.' });
    }
});


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


// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});