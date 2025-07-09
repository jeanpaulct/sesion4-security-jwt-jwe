const jwt = require('jsonwebtoken');
let jose;

// Dynamically import jose
import('jose').then(module => {
    jose = module;
}).catch(err => {
    console.error("Failed to load jose module:", err);
});

const songs = [
    { title: 'Song 1', artist: 'Artist 1' },
    { title: 'Song 2', artist: 'Artist 2' },
    { title: 'Song 3', artist: 'Artist 3' },
];

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // Use environment variable
const JWE_SECRET = process.env.JWE_SECRET || '63d9dae018dff087350438b9988f153f8c261900fd4d9145436fa41ce840509e7c9bb889222ecd91858f7cf0f77986a948d12f2a4b99bffe54e852d3a6c8cce0';//node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

// Helper function to generate a JWE key (for demonstration purposes)
async function generateJWEKey() {
    // Convert hex string to Buffer, then to Uint8Array
    return Buffer.from(JWE_SECRET, 'hex');
}

let jweKey; // Store the generated key

generateJWEKey().then(key => {
    jweKey = key;
}).catch(err => {
    console.error("Failed to generate JWE key:", err);
});

exports.getLogin = (req, res) => {
    res.render('login', { message: req.query.message });
};

exports.redirectIfLoggedIn = async (req, res, next) => {

    const encryptedToken = req.cookies.token;

    if (encryptedToken) {
        try {
            // Decrypt the token using JWE
            const { plaintext } = await jose.compactDecrypt(encryptedToken, jweKey);
            const token = new TextDecoder().decode(plaintext);

            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (!err) {
                    return res.redirect('/dashboard');
                }
                next(); // Token invalid, proceed to next middleware (e.g., login page)
            });
        } catch (err) {
            console.error("JWE Decryption Error:", err);
            next();
        }
    } else {
        next(); // No token, proceed to next middleware
    }
};

exports.postLogin = async (req, res) => {
    const { username, password } = req.body;

    if (username === 'user' && password === 'password') {
        const token = jwt.sign({ username: username }, JWT_SECRET, { expiresIn: '1m' });
        
        // Encrypt the token using JWE
        const encryptedToken = await new jose.CompactEncrypt(
            new TextEncoder().encode(token)
        )
        .setProtectedHeader({ alg: 'dir', enc: 'A256CBC-HS512' })
        .encrypt(jweKey);

        res.cookie('token', encryptedToken, { httpOnly: true });
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

exports.verifyToken = async (req, res, next) => {
    const encryptedToken = req.cookies.token;

    if (!encryptedToken) {
        return res.redirect('/login?message=Please log in to view this page');
    }

    try {
        // Decrypt the token using JWE
        const { plaintext } = await jose.compactDecrypt(encryptedToken, jweKey);
        const token = new TextDecoder().decode(plaintext);

        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.redirect('/login?message=Invalid or expired token');
            }
            req.username = decoded.username; // Attach username to request
            next();
        });
    } catch (err) {
        console.error("JWE Decryption Error:", err);
        return res.redirect('/login?message=Invalid or malformed token');
    }
};
