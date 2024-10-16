const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const usersdata = require('../db');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const e = require("express");
require('dotenv').config();

router.post("/api/register", async (req, res) => {
    const { name, email, password, repeat_password } = req.body;
    const role = req.body.role || 'user';
    try {
        if (password !== repeat_password) {
            return res.redirect('/register?message=Passwords do not match');
        }
        const DuplicateEmail = usersdata.find(user => user.email === email);
        if (DuplicateEmail) {
            return res.redirect('/register?message=E-mail already exists');
        }
        const salt = 10;
        const hashedPassword = await bcrypt.hash(password, salt);
        usersdata.push({ id: usersdata.length + 1, name, email, password: hashedPassword, role });
        res.redirect('/register?message=Registration successful');

    } catch (error) {
        console.log('error', error);
        res.json({
            message: 'Registration failed',
            error
        });
    }
})

function generateOTP(email) {
    return speakeasy.totp({
        secret: email,
        encoding: 'base32',
        step: 300
    });
}

async function sendOTPViaEmail(email, otp) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.pass,
        }
    });

    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'OTP Verification',
        text: `Your OTP is: ${otp}`,
    };
    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent: ' + info.response);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

function verifyOTP(email, otp) {
    const secret = email;
    return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token: otp,
        window: 1,
        step: 300
    });
}

router.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    const userData = usersdata.find(user => user.email === email);
    try {
        const match = await bcrypt.compare(password, userData.password)
        if (match) {
            const otp = generateOTP(email);
            await sendOTPViaEmail(email, otp);
            res.redirect('/verifyotp?email=' + email);
        } else {
            res.redirect('/login?message=Login failed')
        }

    } catch (error) {
        console.log('error', error);
        res.redirect('/login?message=Login failed')
    }
})

router.post("/api/verifyotp", (req, res) => {
    const { email, otp } = req.body;
    const isVerified = verifyOTP(email, otp);
    if (isVerified) {
        const secretKey = 'secretKey';
        const token = jwt.sign({ email }, secretKey, { expiresIn: '1h' });
        res.cookie('token', token, { maxAge: 3600000, httpOnly: true });

        const userData = usersdata.find(user => user.email === email);
        if (userData.role === 'admin') {
            res.redirect('/admin');
        } else {
            res.redirect('/user');
        }
    } else {
        res.redirect('/verifyotp?message=Invalid OTP&email=' + email);
    }
})

router.get("/api/logout", (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
})

module.exports = { router, usersdata }