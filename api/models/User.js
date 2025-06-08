const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    telegramUsername: { type: String, required: true, unique: true, trim: true },
    // Removed 'default: null' so the field is omitted if not provided, allowing sparse index to work
    telegramChatId: { type: String, unique: true, sparse: true }, // Linked Telegram chat ID
    // Removed 'default: null' so the field is omitted if not provided, allowing sparse index to work
    apiKey: { type: String, unique: true, sparse: true }, // One-time API key
    apiKeyGeneratedAt: { type: Date, default: null }, // Timestamp for API key expiry
    balance: { type: Number, default: 0.00 },
    cpmRate: { type: Number, default: 5.00 }, // Default CPM rate per 1000 views
    totalViews: { type: Number, default: 0 }, // Total views for the user
    usdtAddress: { type: String, default: null, trim: true },
    isAdmin: { type: Boolean, default: false },
    isBlocked: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('User', userSchema);
