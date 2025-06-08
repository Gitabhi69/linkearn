const mongoose = require('mongoose');

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    usdtAddress: { type: String, required: true, trim: true },
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
    requestDate: { type: Date, default: Date.now },
    processedDate: { type: Date, default: null }, // Date when admin approves/rejects
});

module.exports = mongoose.model('Withdrawal', withdrawalSchema);
