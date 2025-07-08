const songs = [
    { title: 'Song 1', artist: 'Artist 1' },
    { title: 'Song 2', artist: 'Artist 2' },
    { title: 'Song 3', artist: 'Artist 3' },
];

exports.getLogin = (req, res) => {
    res.render('login', { message: req.query.message });
};

exports.postLogin = (req, res) => {
    const { username, password } = req.body;

    // Simple hardcoded authentication for demonstration
    if (username === 'user' && password === 'password') {
        // In a real application, you would generate a JWT here
        res.redirect('/dashboard');
    } else {
        res.redirect('/login?message=Invalid username or password');
    }
};

exports.getDashboard = (req, res) => {
    // In a real application, you would verify the JWT here
    res.render('dashboard', { songs: songs });
};

exports.logout = (req, res) => {
    // In a real application, you would clear the JWT here
    res.redirect('/login?message=Logged out successfully');
};
