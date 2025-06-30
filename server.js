// =================================================================
//                      Required Packages
// =================================================================
const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg'); // PostgreSQL client

// =================================================================
//                  Initial Application Setup
// =================================================================
const app = express();

// Middleware to allow cross-origin requests and parse JSON bodies
app.use(cors());
app.use(express.json());

// =================================================================
//                  Database and Secrets
// =================================================================

// --- DEBUGGING STEP ---
console.log('DATABASE_URL from environment:', process.env.DATABASE_URL);
// --- END DEBUGGING STEP ---

// It's best practice to get these from environment variables
const connectionString = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

// Create a new pool of connections to the database
const pool = new Pool({
  connectionString: connectionString,
});

// =================================================================
//                      API Endpoints
// =================================================================

// --- User Registration Endpoint ---
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Basic validation
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  try {
    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    const newUser = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );

    res.status(201).json({
      message: 'User registered successfully!',
      user: newUser.rows[0],
    });
  } catch (error) {
    console.error('Registration error:', error);
    // Check for a unique constraint violation (duplicate username)
    if (error.code === '23505') {
      return res.status(400).json({ message: 'Username already exists.' });
    }
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});


// --- User Login Endpoint ---
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Basic validation
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  try {
    // Find the user in the database
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    // If user doesn't exist, send an error
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Compare the submitted password with the stored hashed password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (isPasswordCorrect) {
      // If the password is correct, create a JWT
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '1d' } // Token will expire in one day
      );

      // Send the token back to the client
      res.json({
        success: true,
        message: 'Login successful!',
        token: token,
      });
    } else {
      // If the password is not correct, send an error
      res.status(401).json({ message: 'Invalid credentials.' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});

// =================================================================
//                      Start the Server
// =================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});