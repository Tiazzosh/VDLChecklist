require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());

// Import and use routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');

app.use('/', authRoutes); // Handles /login, /forgot-password, etc.
app.use('/api', userRoutes); // Handles /api/register, /api/users, etc.

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});