const mongoose = require('mongoose');

const earningSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    date: { type: Date, required: true }, // Date representing the start of the IST day
    linkId: { type: mongoose.Schema.Types.ObjectId, ref: 'Link', default: null }, // Link that generated this earning (if per-view)
    views: { type: Number, default: 0 } // Number of views contributing to this earning record for the day
});

// Compound index for efficient daily earnings aggregation
earningSchema.index({ userId: 1, date: 1 }, { unique: false });

module.exports = mongoose.model('Earning', earningSchema);
