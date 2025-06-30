// server.js - Upgraded for a real database

const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const { Pool } = require('pg'); // PostgreSQL client

// --- Database Connection ---
// Store your connection string securely as an environment variable
const connectionString = process.env.DATABASE_URL;
const pool = new Pool({ connectionString });

// ... (rest of the server setup) ...

// --- Updated /register endpoint ---
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    // ... (validation logic) ...
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the PostgreSQL database
    try {
        await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2)',
            [username, hashedPassword]
        );
        res.status(201).json({ message: "User registered successfully!" });
    } catch (dbError) {
        // Handle potential database errors, e.g., duplicate username
        res.status(400).json({ message: "Username may already be taken." });
    }
});