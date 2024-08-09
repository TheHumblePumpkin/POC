const express = require('express');
const userController = require('../Controllers/userController');
const authMiddleware = require('../Middleware/authMiddleware');
const router = express.Router();

router.post('/register', userController.register);
router.post('/login', userController.login);

// Protected routes
router.get('/', authMiddleware, userController.getAllUsers);
router.get('/:id', authMiddleware, userController.getUserById);
router.put('/:id', authMiddleware, userController.updateUser);
router.delete('/:id', authMiddleware, userController.deleteUser);

module.exports = router;
