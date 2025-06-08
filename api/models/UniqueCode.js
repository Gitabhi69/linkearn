const mongoose = require('mongoose');

const uniqueCodeSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true, trim: true, uppercase: true },
    isActive: { type: Boolean, default: true },
    createdDate: { type: Date, default: Date.now },
    expiryDate: { type: Date, default: null }, // Null means never expires
});

module.exports = mongoose.model('UniqueCode', uniqueCodeSchema);
