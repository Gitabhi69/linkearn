const { v4: uuidv4 } = require('uuid');
const { DateTime } = require('luxon');

// Generate a 5-digit unique code
const generateUniqueCode = () => {
    return Math.random().toString(36).substring(2, 7).toUpperCase();
};

// Generate a short unique ID for links
const generateShortUniqueId = () => {
    // Using a portion of UUID for brevity and reasonable uniqueness
    return uuidv4().split('-')[0].toUpperCase();
};

// Get start of IST day for earnings calculation
const getStartOfISTDay = (date = new Date()) => {
    // Ensure 'Asia/Kolkata' timezone for IST calculations
    return DateTime.fromJSDate(date, { zone: 'Asia/Kolkata' }).startOf('day').toJSDate();
};

// Basic USDT BEP20 address validation (starts with 0x and is 42 chars long)
const isValidUsdtAddress = (address) => {
    return /^0x[a-fA-F0-9]{40}$/i.test(address);
};

module.exports = {
    generateUniqueCode,
    generateShortUniqueId,
    getStartOfISTDay,
    isValidUsdtAddress
};
