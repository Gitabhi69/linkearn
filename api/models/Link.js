const mongoose = require('mongoose');

const linkSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    uniqueId: { type: String, required: true, unique: true }, // Short unique ID for the link
    mediaFileId: { type: String, required: true }, // Telegram file_id of the stored media
    generatedLink: { type: String, required: true }, // Full Telegram Mini App link
    viewCount: { type: Number, default: 0 }, // Number of actual views (ad completed + media delivered)
    createdDate: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true }, // Can be set to false for deletion
    // To track views per user (anti-fraud for counting views once per unique viewer)
    viewers: [{
        viewerTelegramId: { type: String, required: true },
        viewedAt: { type: Date, default: Date.now }
    }]
});

module.exports = mongoose.model('Link', linkSchema);
