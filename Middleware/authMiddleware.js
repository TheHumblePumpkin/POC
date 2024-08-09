const jwt = require('jsonwebtoken');
const User = require('../Models/userSchema');

const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '').trim();
        if (!token) {
            console.log('No token provided');
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        //console.log('Token decoded:', decoded);

        // Fetch user details using the ID from the token and attaching to response object
        const user = await User.findById(decoded.id);
        if (!user) {
            console.log('User not found');
            return res.status(401).json({ message: 'User not found' });
        }

        req.user = {
            _id: user._id,
            email: user.email,
            role: user.role
        };

        next();
    } catch (error) {
        console.log('Token verification failed:', error.message);
        return res.status(401).json({ message: 'Invalid token' });
    }
}

module.exports = auth;
