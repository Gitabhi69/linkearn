const mongoose = require('mongoose');

const adminSettingSchema = new mongoose.Schema({
    _id: { type: String, default: 'globalSettings' }, // Ensure only one document exists
    minWithdrawal: { type: Number, default: 100.00 },
    defaultCPM: { type: Number, default: 5.00 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('AdminSetting', adminSettingSchema);
