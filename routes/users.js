const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

module.exports = function(pool) {
    const router = express.Router();

    // --- Middleware (Specific to this router) ---
    const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token == null) return res.sendStatus(401);

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
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

    // === ROUTES ===
    // All routes in this file are automatically prefixed with /api

    // GET /api/users
    router.get('/users', authenticateToken, isAdmin, async (req, res) => {
        try {
            const result = await pool.query('SELECT id, username, name, surname, email, job_role, is_admin FROM users ORDER BY id');
            res.json(result.rows);
        } catch (error) {
            console.error('Error fetching users:', error);
            res.status(500).json({ message: 'An error occurred on the server.' });
        }
    });

    // POST /api/register
    router.post('/register', authenticateToken, isAdmin, async (req, res) => {
        const { username, password, name, surname, email, job_role } = req.body;
        if (!username || !password || !name || !surname || !email || !job_role) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.query(
                'INSERT INTO users (username, password, name, surname, email, job_role, is_admin) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                [username, hashedPassword, name, surname, email, job_role, false]
            );
            res.status(200).json({ message: 'User registered successfully!' });
        } catch (error) {
            console.error('Registration error:', error);
            if (error.code === '23505') {
                return res.status(400).json({ message: 'Username or email already exists.' });
            }
            res.status(500).json({ message: 'An error occurred on the server.' });
        }
    });

    // POST /api/user/change-password
    router.post('/user/change-password', authenticateToken, async (req, res) => {
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
            console.error('Change password error:', error);
            res.status(500).json({ message: 'Server error.' });
        }
    });

    return router;
};