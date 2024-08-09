const jwt = require('jsonwebtoken');
const User = require('../Models/userSchema');
const auth = require('../Middleware/authMiddleware');

jest.mock('jsonwebtoken');
jest.mock('../Models/userSchema');

// Test cases for authMiddleware
// Four cases: 1. Call next() if token is valid and user is found, 2. Return 401 if no token is provided, 3. Return 401 if token is invalid, 4. Return 401 if user is not found
describe('Auth Middleware', () => {
    let req, res, next;

    //Mocking express middkeware functions
    beforeEach(() => {
        req = {
            header: jest.fn().mockReturnValue('Bearer valid_token'),
        };
        res = {
            status: jest.fn(() => res),
            json: jest.fn(() => res),
        };
        next = jest.fn();
    });

    it('should call next() method only if token is valid and user is found', async () => {
        jwt.verify.mockReturnValue({ id: 'user_id' });
        User.findById.mockResolvedValue({
            _id: 'user_id',
            email: 'testuser@example.com',
            role: 'user',
        });

        await auth(req, res, next);

        expect(jwt.verify).toHaveBeenCalledWith('valid_token', process.env.JWT_SECRET);
        expect(User.findById).toHaveBeenCalledWith('user_id');
        expect(req.user).toEqual({
            _id: 'user_id',
            email: 'testuser@example.com',
            role: 'user',
        });
        expect(next).toHaveBeenCalled();
    });

    it('should return 401 if no token is provided', async () => {
        req.header = jest.fn().mockReturnValue('');

        await auth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if token is invalid', async () => {
        jwt.verify.mockImplementation(() => {
            throw new Error('Invalid token');
        });

        await auth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Invalid token' });
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if user is not found', async () => {
        jwt.verify.mockReturnValue({ id: 'user_id' });
        User.findById.mockResolvedValue(null);

        await auth(req, res, next);

        expect(User.findById).toHaveBeenCalledWith('user_id');
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'User not found' });
        expect(next).not.toHaveBeenCalled();
    });
});
