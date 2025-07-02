require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Middleware to handle CORS and preflight requests
app.options('*', cors()); // Handles the preflight OPTIONS request
app.use(cors({ origin: '*' })); // Handles the actual requests
app.use(express.json());

// Import and use routes
const authRoutes = require('./routes/auth')(pool);
const userRoutes = require('./routes/users')(pool);

app.use('/', authRoutes);
app.use('/api', userRoutes);

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});