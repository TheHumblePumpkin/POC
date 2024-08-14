const mongoose = require('mongoose');

// Mock the Mongoose connect method before all tests
beforeAll(async () => {
    jest.spyOn(mongoose, 'connect').mockImplementation(() => Promise.resolve());
});

// Restore all mocks after all tests
afterAll(async () => {
    jest.restoreAllMocks();
});
