const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const path = require('path');
const cors = require('cors');

const app = express();

// In-memory store for tokens (for testing only)
const tokenStore = new Map();

// Enable CORS for requests from http://localhost:5173 (Vite dev server)
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Handle CORS preflight requests
app.options('/api/user', cors());

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    next();
});

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
clientID: process.env.GOOGLE_CLIENT_ID,
clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3002/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
    console.log('OAuth2 Callback: User authenticated', {
        id: profile.id,
        displayName: profile.displayName,
        email: profile.emails[0].value
    });
    const user = {
        id: profile.id,
        displayName: profile.displayName,
        email: profile.emails[0].value,
        token: accessToken
    };
    // Store the token in memory
    tokenStore.set(accessToken, user);
    return done(null, user);
}));

passport.serializeUser((user, done) => {
    console.log('Serializing user:', user);
    done(null, user);
});

passport.deserializeUser((obj, done) => {
    console.log('Deserializing user:', obj);
    done(null, obj);
});

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    console.log('Serving homepage');
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account'
}));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        console.log('OAuth2 Callback: Authentication successful');
        const accessToken = req.user.token;
        
        const htmlResponse = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Authorization Successful</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        margin-top: 50px;
                        background-color: #f0f0f0;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    a {
                        color: #4285f4;
                        text-decoration: none;
                    }
                    a:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Authorization was successful.</h2>
                    <p>You will be redirected back to app.</p>
                    <p>You can now close this window. If you are not redirected automatically, 
                       <a href="/">click here</a>.</p>
                </div>
                <script>
                    setTimeout(function() {
                        window.location.href = '/';
                    }, 3000);
                </script>
            </body>
            </html>
        `;
        res.send(htmlResponse);

        const http = require('http');
        const callbackUrl = `http://localhost:8888/callback?token=${accessToken}`;
        console.log('Notifying Electron app at:', callbackUrl);
        const request = http.get(callbackUrl, (pythonRes) => {
            console.log('Electron app notified, status:', pythonRes.statusCode);
            let data = '';
            pythonRes.on('data', (chunk) => {
                data += chunk;
            });
            pythonRes.on('end', () => {
                console.log('Electron app response:', data);
            });
        });
        request.on('error', (e) => {
            console.error('Error notifying Electron app:', e.message);
            console.error('Error details:', e);
        });
        request.end();
    }
);

app.get('/user', (req, res) => {
    console.log('User endpoint called:', req.isAuthenticated() ? req.user : 'Not authenticated');
    if (req.isAuthenticated()) {
        res.json(req.user);
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

app.get('/api/user', (req, res) => {
    console.log('API/User endpoint called');
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('No Bearer token provided');
        return res.status(401).json({ error: 'No Bearer token provided' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        console.log('Invalid token format');
        return res.status(401).json({ error: 'Invalid token format' });
    }
    const user = tokenStore.get(token);
    if (user) {
        console.log('User found for token:', user);
        res.json({
            id: user.id,
            displayName: user.displayName,
            email: user.email
        });
    } else {
        console.log('No user found for token:', token);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
});

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
            return next(err);
        }
        console.log('User logged out');
        res.redirect('/');
    });
});

const PORT = 3002;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});