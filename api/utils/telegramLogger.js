// This logger is for the Vercel API. It will only log to the console.
// The actual Telegram logging will be done by the Heroku bot.

const sendLog = (message) => {
    console.log(`[Vercel API Log] ${message}`);
};

module.exports = { sendLog };
