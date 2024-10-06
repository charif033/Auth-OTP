const express = require("express");
const router = express.Router();
const db = require('../db');
const jwt = require('jsonwebtoken');
const secretKey = 'secretKey';

router.get("/", (req, res) => {
    res.redirect('/login');
});

router.get("/login", (req, res) => {
    const message = req.query.message || ''
    res.render('login', { message });
});

router.get("/register", (req, res) => {
    const message = req.query.message || ''
    res.render('register', { message });
});

router.get("/admin", async (req, res) => {
    if (req.cookies.token) {
        const token = req.cookies.token;
        jwt.verify(token, secretKey, async (err, decoded) => {
            const [results] = await db.promise().query("SELECT * FROM users WHERE username = ?", decoded.username)

            if (err) {
                return res.redirect('/login');
            } else if (results[0].role === 'user') {
                return res.redirect('/user');
            }

            const [allusers] = await db.promise().query("SELECT * FROM users")

            return res.render('admin', {
                name: results[0].name,
                username: results[0].username,
                allUsers: allusers
            });
        });
    } else {
        console.log('No token found in cookies');
        return res.redirect('/login');
    };
});

router.get("/user", async (req, res) => {
    if (req.cookies.token) {
        const token = req.cookies.token;
        jwt.verify(token, secretKey, async (err, decoded) => {
            const [results] = await db.promise().query("SELECT * FROM users WHERE username = ?", decoded.username)

            if (err) {
                return res.redirect('/login');
            } else if (results[0].role === 'admin') {
                return res.redirect('/admin');
            }

            return res.render('user', {
                name: results[0].name,
                username: results[0].username,
                role: results[0].role
            });
        });
    } else {
        console.log('No token found in cookies');
        return res.redirect('/login');
    };
});

module.exports = router