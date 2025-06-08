const crypto = require('crypto');
const querystring = require('querystring'); // Needed for URLSearchParams

// Function to validate Telegram WebApp InitData
// This is crucial for security against ad fraud
const validateInitData = (req, res, next) => {
    // initData is expected in the request body as a raw string
    const initDataRaw = req.body.initDataRaw;
    const uniqueId = req.body.uniqueId; // uniqueId passed from Mini App

    if (!initDataRaw || !uniqueId) {
        return res.status(400).json({ message: 'Missing initData or uniqueId' });
    }

    try {
        const urlParams = new URLSearchParams(initDataRaw);
        const hash = urlParams.get('hash');
        urlParams.delete('hash');

        // Sort parameters for dataCheckString as per Telegram spec
        const dataCheckString = Array.from(urlParams.entries())
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([key, value]) => `${key}=${value}`)
            .join('\n');

        // Secret key is HMAC-SHA256 of 'WebAppData' with the bot token
        // IMPORTANT: The bot token is needed here for validation.
        // If your Vercel backend and Heroku bot are truly separate,
        // you MUST store the BOT_TOKEN in Vercel's environment variables as well.
        // It's a security risk to put it in client-side JS.
        const secret = crypto.createHmac('sha256', 'WebAppData')
            .update(process.env.BOT_TOKEN_FOR_INITDATA_VALIDATION) // Use a specific env var for clarity
            .digest();

        // Calculate the hash of the data-check-string with the secret key
        const calculatedHash = crypto.createHmac('sha256', secret)
            .update(dataCheckString)
            .digest('hex');

        if (calculatedHash !== hash) {
            console.warn('InitData Validation Failed: Hash mismatch');
            return res.status(403).json({ message: 'Invalid initData hash' });
        }

        // Extract user information from initData (e.g., id, first_name)
        const userString = urlParams.get('user');
        const userData = userString ? JSON.parse(userString) : null;
        if (!userData || !userData.id) {
            console.warn('InitData Validation Failed: User ID missing');
            return res.status(403).json({ message: 'User information missing in initData' });
        }

        req.viewerTelegramId = userData.id.toString(); // Attach viewer's Telegram ID to request
        next();
    } catch (error) {
        console.error('Error validating initData:', error);
        res.status(500).json({ message: 'Failed to validate initData' });
    }
};

module.exports = { validateInitData };
