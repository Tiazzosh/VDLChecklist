require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();

//Create the DB pool once
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Middleware
app.options('*', cors()); // Handle preflight requests
app.use(cors({ origin: '*' }));
app.use(express.json());

// Import and use routes, passsing the pool to them
const authRoutes = require('./routes/auth')(pool);
const userRoutes = require('./routes/users')(pool);

app.use('/', authRoutes); // Handles /login, /forgot-password, etc.
//app.use('/api', userRoutes); // Handles /api/register, /api/users, etc.

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});