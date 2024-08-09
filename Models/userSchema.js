const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    role: {type: String, default: 'user'},
});

userSchema.pre('save', async function(next) {
    try {
        if(this.isModified('password')) {
            this.password = await bcrypt.hash(this.password, 10);
        }
        next();
    } catch (error) {
        next(error);
    }
});

userSchema.methods.comparePassword = async function(savedPassword, next) {
    try {
        const isMatch = await bcrypt.compare(savedPassword, this.password);
        return isMatch;
    } catch (error) {
        next(error);
    }
}

module.exports = mongoose.model('User', userSchema);
