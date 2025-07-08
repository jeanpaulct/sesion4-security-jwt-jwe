const jwt = require('jsonwebtoken');

const songs = [
    { title: 'Song 1', artist: 'Artist 1' },
    { title: 'Song 2', artist: 'Artist 2' },
    { title: 'Song 3', artist: 'Artist 3' },
];

const JWT_SECRET = 'your_jwt_secret_key'; // Replace with a strong, unique secret in production

exports.getLogin = (req, res) => {
    res.render('login', { message: req.query.message });
};

exports.postLogin = (req, res) => {
    const { username, password } = req.body;

    if (username === 'user' && password === 'password') {
        const token = jwt.sign({ username: username }, JWT_SECRET, { expiresIn: '1m' });
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/dashboard');
    } else {
        res.redirect('/login?message=Invalid username or password');
    }
};

exports.getDashboard = (req, res) => {
    res.render('dashboard', { songs: songs });
};

exports.logout = (req, res) => {
    res.clearCookie('token');
    res.redirect('/login?message=Logged out successfully');
};

exports.verifyToken = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login?message=Please log in to view this page');
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.redirect('/login?message=Invalid or expired token');
        }
        req.username = decoded.username; // Attach username to request
        next();
    });
};
