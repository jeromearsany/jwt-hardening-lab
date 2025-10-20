// --- Hardened JWT Server for Assignment 2 ---
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, './.env') });
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('./users.db');
app.use(bodyParser.json());
app.use(express.static('public'));

// --- Requirement 1 & 2: Load secrets from .env file ---
const ACCESS_TOKEN_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ACCESS_TOKEN_LIFETIME = process.env.ACCESS_TOKEN_LIFETIME;
const REFRESH_TOKEN_LIFETIME = process.env.REFRESH_TOKEN_LIFETIME;
const TOKEN_ISSUER = process.env.TOKEN_ISSUER;
const TOKEN_AUDIENCE = process.env.TOKEN_AUDIENCE;

// --- Requirement 4: Store for refresh tokens (in-memory for this lab) ---
const refreshStore = new Map();

// --- Login Endpoint ---
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                // --- Requirement 3: Enforce token claims and verification ---
                const accessTokenPayload = { userId: user.id, username: user.username, role: user.role };
                const accessToken = jwt.sign(accessTokenPayload, ACCESS_TOKEN_SECRET, {
                    expiresIn: ACCESS_TOKEN_LIFETIME,
                    audience: TOKEN_AUDIENCE,
                    issuer: TOKEN_ISSUER,
                    algorithm: 'HS256'
                });

                // --- Requirement 4: Issue a refresh token ---
                const tokenId = require('crypto').randomBytes(16).toString('hex'); // Create a unique ID for the refresh token
                const refreshTokenPayload = { userId: user.id, username: user.username, tokenId: tokenId };
                const refreshToken = jwt.sign(refreshTokenPayload, REFRESH_TOKEN_SECRET, {
                    expiresIn: REFRESH_TOKEN_LIFETIME,
                    audience: TOKEN_AUDIENCE,
                    issuer: TOKEN_ISSUER,
                    algorithm: 'HS256'
                });

                refreshStore.set(tokenId, user.username); // Store the token ID as valid

                res.json({ accessToken, refreshToken });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
});

// --- Requirement 4: Refresh Token Endpoint ---
app.post('/refresh', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token not provided' });
    }

    const verificationOptions = { audience: TOKEN_AUDIENCE, issuer: TOKEN_ISSUER, algorithms: ['HS256'] };

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, verificationOptions, (err, payload) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        // Check if the refresh token is still valid in our store
        if (!refreshStore.has(payload.tokenId) || refreshStore.get(payload.tokenId) !== payload.username) {
            return res.status(403).json({ error: 'Refresh token has been invalidated' });
        }

        // Token is valid, issue a new access token
        const accessTokenPayload = { userId: payload.userId, username: payload.username, role: payload.role };
        const newAccessToken = jwt.sign(accessTokenPayload, ACCESS_TOKEN_SECRET, {
            expiresIn: ACCESS_TOKEN_LIFETIME,
            audience: TOKEN_AUDIENCE,
            issuer: TOKEN_ISSUER,
            algorithm: 'HS256'
        });

        res.json({ accessToken: newAccessToken });
    });
});

// --- Middleware to protect routes ---
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        const verificationOptions = { audience: TOKEN_AUDIENCE, issuer: TOKEN_ISSUER, algorithms: ['HS256'] };
        jwt.verify(token, ACCESS_TOKEN_SECRET, verificationOptions, (err, user) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid or expired access token' });
            }
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({ error: 'Authorization header is missing' });
    }
};

// --- A protected route to test the token ---
app.get('/profile', authenticateJWT, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}! Your role is: ${req.user.role}. This is a protected area.` });
});


// --- Start the server ---
app.listen(1234, () => {
    console.log('HARDENED JWT server running on http://localhost:1234');
});