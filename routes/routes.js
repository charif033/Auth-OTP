const express = require("express");
const router = express.Router();
const { usersdata } = require('./api');
const jwt = require('jsonwebtoken');
const secretKey = 'secretKey';
const ratelimit = require('express-rate-limit');

const limiter = ratelimit({
    windowMs: 60 * 1000,
    max: 5,
    message: 'Too many requests, please try again later'
});

router.get("/", (req, res) => {
    res.redirect('/login');
});

router.get("/login", limiter, (req, res) => {
    const message = req.query.message || ''
    res.render('login', { message });
});

router.get("/register", limiter, (req, res) => {
    const message = req.query.message || ''
    res.render('register', { message });
});

router.get("/verifyotp", (req, res) => {
    const message = req.query.message || ''
    const email = req.query.email || ''
    res.render('verifyotp', { message, email });
});

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login');
    }
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.redirect('/login');
        }
        req.user = decoded;
        next();
    });
}

router.get("/admin", verifyToken, async (req, res) => {
    const decoded = req.user;
    const userDecodedData = usersdata.find(user => user.email === decoded.email);

    if (userDecodedData.role === 'user') {
        return res.redirect('/user');
    } else {
        return res.render('admin', {
            name: userDecodedData.name,
            allUsers: usersdata
        });
    }
});

router.get("/user", verifyToken, async (req, res) => {
    const decoded = req.user;
    const userDecodedData = usersdata.find(user => user.email === decoded.email);

    if (userDecodedData.role === 'admin') {
        return res.redirect('/admin');
    } else {
        return res.render('user', {
            name: userDecodedData.name,
            email: userDecodedData.email,
            role: userDecodedData.role
        });
    }
});

module.exports = router