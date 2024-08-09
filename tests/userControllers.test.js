const request = require('supertest');
const app = require('../app');
const User = require('../Models/userSchema');
const jwt = require('jsonwebtoken');
const authMiddleware = require('../Middleware/authMiddleware');

// Mock Mongoose model
jest.mock('../Models/userSchema');

// Mock jwt
jest.mock('jsonwebtoken', () => ({
    sign: jest.fn(() => 'mocked_jwt_token')
}));

// Mock authMiddleware 
jest.mock('../Middleware/authMiddleware', () => jest.fn((req, res, next) => next()));

//1. Testing User Registration
// Two cases: 1. User registration with valid input, 2. User registration with invalid input
describe('User Registration', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    it('POST /poc/v1/users/register should register a new user', async () => {
        // Mock save method
        User.prototype.save = jest.fn().mockResolvedValueOnce({
            _id: 'mocked_user_id',
            email: 'testuser@example.com',
            password: 'hashed_password'
        });

        const response = await request(app)
            .post('/poc/v1/users/register')
            .send({
                email: 'testuser@example.com',
                password: 'password123'
            });

        expect(response.status).toBe(201);
        expect(response.body.message).toBe('User registered successfully');
        expect(User.prototype.save).toHaveBeenCalled();
    });

    it('POST /poc/v1/users/register should fail with invalid input', async () => {
        // Mock save method with error
        User.prototype.save = jest.fn().mockImplementationOnce(() => {
            throw new Error('User validation failed');
        });

        const response = await request(app)
            .post('/poc/v1/users/register')
            .send({
                email: 'invalidemail',
                password: 'short'
            });

        expect(response.status).toBe(400);
        expect(response.body.message).toMatch(/User validation failed/);
    });
});

//2. Testing User Login
// Three cases: 1. User login with correct credentials, 2. User login with incorrect email, 3. User login with incorrect password
describe('User Login', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    it('POST /poc/v1/users/login should login a user and return token', async () => {
        const mockUser = {
            _id: 'mocked_user_id',
            email: 'mockuser@example.com',
            password: 'hashed_password',
            role: 'user',
            comparePassword: jest.fn().mockResolvedValue(true)
        };

        // Mock User.findOne to return the mockUser
        User.findOne.mockResolvedValue(mockUser);

        const response = await request(app)
            .post('/poc/v1/users/login')
            .send({
                email: 'mockuser@example.com',
                password: 'password123'
            });

        expect(response.status).toBe(200);
        expect(response.body.token).toBe('mocked_jwt_token');
        expect(User.findOne).toHaveBeenCalledWith({ email: 'mockuser@example.com' });
        expect(mockUser.comparePassword).toHaveBeenCalledWith('password123');
        expect(jwt.sign).toHaveBeenCalledWith(
            {
                id: 'mocked_user_id',
                email: 'mockuser@example.com',
                role: 'user'
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );
    });

    it('POST /poc/v1/users/login should return 404 if user not found', async () => {
        // Mock User.findOne to return empty result
        User.findOne.mockResolvedValue(null);

        const response = await request(app)
            .post('/poc/v1/users/login')
            .send({
                email: 'nonexistent@example.com',
                password: 'password123'
            });

        expect(response.status).toBe(404);
        expect(response.body.message).toBe('User not found');
        expect(User.findOne).toHaveBeenCalledWith({ email: 'nonexistent@example.com' });
    });

    it('POST /poc/v1/users/login should return 400 if password is incorrect', async () => {
        const mockUser = {
            _id: 'mocked_user_id',
            email: 'mockuser@example.com',
            password: 'hashed_password',
            role: 'user',
            comparePassword: jest.fn().mockResolvedValue(false)
        };

        // Mock User.findOne to return the mockUser
        User.findOne.mockResolvedValue(mockUser);

        const response = await request(app)
            .post('/poc/v1/users/login')
            .send({
                email: 'mockuser@example.com',
                password: 'wrongpassword'
            });

        expect(response.status).toBe(400);
        expect(response.body.message).toBe('Invalid password');
        expect(User.findOne).toHaveBeenCalledWith({ email: 'mockuser@example.com' });
        expect(mockUser.comparePassword).toHaveBeenCalledWith('wrongpassword');
    });    
});

//3. Testing User Retrieval
// Three cases: 1. Retrieve all users, 2. Retrieve a user by ID, 3. Retrieve a user by non-existent ID
describe('User Retrieval', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    it('GET /poc/v1/users should return all users', async () => {
        // Mock the find method
        User.find.mockResolvedValueOnce([
            { _id: 'user1_id', email: 'user1@example.com', role: 'user' },
            { _id: 'user2_id', email: 'user2@example.com', role: 'admin' }
        ]);

        const response = await request(app).get('/poc/v1/users');

        expect(response.status).toBe(200);
        expect(response.body).toEqual([
            { _id: 'user1_id', email: 'user1@example.com', role: 'user' },
            { _id: 'user2_id', email: 'user2@example.com', role: 'admin' }
        ]);
        expect(User.find).toHaveBeenCalled();
    });

    it('GET /poc/v1/users/:id should return a user by ID', async () => {
        // Mock the findById method
        User.findById.mockResolvedValueOnce({
            _id: 'user1_id',
            email: 'user1@example.com',
            role: 'user'
        });

        const response = await request(app).get('/poc/v1/users/user1_id');

        expect(response.status).toBe(200);
        expect(response.body).toEqual({
            _id: 'user1_id',
            email: 'user1@example.com',
            role: 'user'
        });
        expect(User.findById).toHaveBeenCalledWith('user1_id');
    });

    it('GET /poc/v1/users/:id should return 404 if user not found', async () => {
        // Mock the findById method to return null
        User.findById.mockResolvedValueOnce(null);

        const response = await request(app).get('/poc/v1/users/nonexistent_id');

        expect(response.status).toBe(404);
        expect(response.body.message).toBe('User not found');
        expect(User.findById).toHaveBeenCalledWith('nonexistent_id');
    });
});

// 4. Testing User Update
// Two cases: 1. Update a user with valid input, 2. Update a user with non-existent ID
describe('User Update', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    it('PUT /poc/v1/users/:id should update a user', async () => {
        // Mock the findByIdAndUpdate method
        User.findByIdAndUpdate.mockResolvedValueOnce({
            _id: 'user1_id',
            email: 'updateduser@example.com',
            role: 'user'
        });

        const response = await request(app)
            .put('/poc/v1/users/user1_id')
            .set('Content-Type', 'application/json') // Set the content type to JSON here
            .send({
                email: 'updateduser@example.com'
            });

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('User updated successfully');
        expect(response.body.user).toEqual({
            _id: 'user1_id',
            email: 'updateduser@example.com',
            role: 'user'
        });
        expect(User.findByIdAndUpdate).toHaveBeenCalledWith(
            'user1_id',
            { email: 'updateduser@example.com' },
            { new: true }
        );
    });

    it('PUT /poc/v1/users/:id should return 404 if user not found', async () => {
        // Mock the findByIdAndUpdate method to return null
        User.findByIdAndUpdate.mockResolvedValueOnce(null);

        const response = await request(app)
            .put('/poc/v1/users/nonexistent_id')
            .set('Content-Type', 'application/json')
            .send({
                email: 'updateduser@example.com'
            });

        expect(response.status).toBe(404);
        expect(response.body.message).toBe('User not found');
        expect(User.findByIdAndUpdate).toHaveBeenCalledWith(
            'nonexistent_id',
            { email: 'updateduser@example.com' },
            { new: true }
        );
    });
});

// 5. Testing User Deletion
// Two cases: 1. Delete a user, 2. Delete a non-existent user
describe('User Deletion', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    it('DELETE /poc/v1/users/:id should delete a user', async () => {
        // Mock the findByIdAndDelete method
        User.findByIdAndDelete.mockResolvedValueOnce({
            _id: 'user1_id',
            email: 'user1@example.com',
            role: 'user'
        });

        const response = await request(app).delete('/poc/v1/users/user1_id');

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('User deleted successfully');
        expect(User.findByIdAndDelete).toHaveBeenCalledWith('user1_id');
    });

    it('DELETE /poc/v1/users/:id should return 404 if user not found', async () => {
        // Mock the findByIdAndDelete method to return null
        User.findByIdAndDelete.mockResolvedValueOnce(null);

        const response = await request(app).delete('/poc/v1/users/nonexistent_id');

        expect(response.status).toBe(404);
        expect(response.body.message).toBe('User not found');
        expect(User.findByIdAndDelete).toHaveBeenCalledWith('nonexistent_id');
    });
});
