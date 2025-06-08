const jwt = require('jsonwebtoken');
const User = require('../models/User'); // Adjusted path for Vercel structure

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = await User.findById(decoded.id).select('-password'); // Attach user to request
            if (!req.user) {
                return res.status(401).json({ message: 'Not authorized, user not found' });
            }
            // If user is blocked, disallow access to protected routes
            if (req.user.isBlocked) {
                return res.status(403).json({ message: 'Your account has been blocked. Please contact support.' });
            }
            next();
        } catch (error) {
            console.error(error);
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }
    if (!token) {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

const adminProtect = (req, res, next) => {
    // This middleware assumes `protect` has already run and `req.user` is available
    if (req.user && req.user.isAdmin) {
        next();
    } else {
        res.status(403).json({ message: 'Not authorized as an admin' });
    }
};

module.exports = { protect, adminProtect };
