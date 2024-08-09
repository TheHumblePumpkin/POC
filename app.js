const express = require('express');
const mongoose = require('mongoose');
const userRoutes = require('./Routes/userRoutes');
const app = express();

app.use(express.json());

app.use('/poc/v1/users', userRoutes);

module.exports = app;