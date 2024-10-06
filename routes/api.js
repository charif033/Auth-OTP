const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require('../db');

router.post("/api/register", async (req, res) => {
    try {
        const { name, username, password, repeat_password } = req.body;
        if (password !== repeat_password) {
            return res.redirect('/register?message=Passwords do not match');
        }
        const [search_results] = await db.promise().query("SELECT * FROM users WHERE username = ?", username);
        if (search_results.length > 0) {
            return res.redirect('/register?message=Username already exists');
        }
        const salt = 2;
        const hashedPassword = await bcrypt.hash(password, salt);
        await db.promise().query("INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)", [name, username, hashedPassword, 'user']);
        res.redirect('/register?message=Registration successful');

    } catch (error) {
        console.log('error', error);
        res.json({
            message: 'Registration failed',
            error
        });
    }
})

router.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const [results] = await db.promise().query("SELECT * FROM users WHERE username = ?", username);
        const userData = results[0];
        const match = await bcrypt.compare(password, userData.password)
        if (match) {
            const secretKey = 'secretKey';
            const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
            res.cookie('token', token, { maxAge: 900000, httpOnly: true });
            if (userData.role === 'admin') {
                res.redirect('/admin');
            } else {
                res.redirect('/user');
            }
        } else {
            res.redirect('/login?message=Login failed - wrong password')
        }

    } catch (error) {
        console.log('error', error);
        res.redirect('/login?message=Login failed - wrong username')
    }
})

router.get("/api/logout", (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
})

module.exports = router