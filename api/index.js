require('dotenv').config(); // Load environment variables for local testing
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const NodeCache = require('node-cache'); // For short-lived API key cache
const { DateTime } = require('luxon'); // For timezone handling

// Models (adjusted paths for Vercel's `api` directory)
const User = require('./models/User');
const Link = require('./models/Link');
const Withdrawal = require('./models/Withdrawal');
const UniqueCode = require('./models/UniqueCode');
const Earning = require('./models/Earning');
const AdminSetting = require('./models/AdminSetting');

// Middleware (adjusted paths for Vercel's `api` directory)
const { protect, adminProtect } = require('./middleware/auth');
const { validateInitData } = require('./middleware/initDataValidation');

// Utils (adjusted paths for Vercel's `api` directory)
const { sendLog } = require('./utils/telegramLogger'); // Vercel logger just logs to console
const { generateUniqueCode, getStartOfISTDay, isValidUsdtAddress, generateShortUniqueId } = require('./utils/helpers');

// Initialize Express App
const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for frontend communication

// Initialize API Key Cache (5 minutes expiry for one-time API key)
const apiKeyCache = new NodeCache({ stdTTL: 300, checkperiod: 60 }); // 300 seconds = 5 minutes

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(async () => {
        console.log('MongoDB Connected (Vercel API)');

        // !!! CRITICAL: Forcefully drop and recreate sparse indexes to avoid conflicts !!!
        // This ensures indexes are correctly sparse, especially if they were created
        // before the sparse option was added to the schema.

        // Ensure telegramChatId_1 index is unique and sparse
        try {
            await User.collection.dropIndex('telegramChatId_1').catch(err => {
                if (err.code !== 27) { // Error code 27: index not found
                    console.warn('Could not drop telegramChatId_1 index (might not exist or other issue):', err.message);
                } else {
                    console.log('telegramChatId_1 index not found, no need to drop.');
                }
            });
            console.log('Attempted to drop existing telegramChatId_1 index.');

            await User.collection.createIndex(
                { telegramChatId: 1 }, // Index on telegramChatId in ascending order
                { unique: true, sparse: true, name: 'telegramChatId_1' } // Ensure unique and sparse
            );
            console.log('Ensured telegramChatId_1 index is unique and sparse.');
        } catch (indexError) {
            console.error('CRITICAL: Failed to create telegramChatId_1 index:', indexError.message);
            // This would indicate a very serious MongoDB issue or configuration problem.
        }

        // Ensure apiKey_1 index is unique and sparse
        try {
            await User.collection.dropIndex('apiKey_1').catch(err => {
                if (err.code !== 27) { // Error code 27: index not found
                    console.warn('Could not drop apiKey_1 index (might not exist or other issue):', err.message);
                } else {
                    console.log('apiKey_1 index not found, no need to drop.');
                }
            });
            console.log('Attempted to drop existing apiKey_1 index.');

            await User.collection.createIndex(
                { apiKey: 1 }, // Index on apiKey in ascending order
                { unique: true, sparse: true, name: 'apiKey_1' } // Ensure unique and sparse
            );
            console.log('Ensured apiKey_1 index is unique and sparse.');
        } catch (indexError) {
            console.error('CRITICAL: Failed to create apiKey_1 index:', indexError.message);
        }

        // Ensure default admin user exists (for initial login)
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@linkearn.com';
        const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

        const adminUser = await User.findOne({ email: adminEmail, isAdmin: true });
        if (!adminUser) {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(adminPassword, salt);
            await User.create({
                fullName: 'Admin',
                email: adminEmail,
                password: hashedPassword,
                telegramUsername: '@linkearn_admin_default', // Placeholder, not used by bot
                isAdmin: true,
                balance: 0,
                cpmRate: 0 // Admin doesn't earn CPM
            });
            console.log('Default admin user created.');
        }

        // Ensure initial "MONEY" unique code exists
        const moneyCode = await UniqueCode.findOne({ code: 'MONEY' });
        if (!moneyCode) {
            await UniqueCode.create({ code: 'MONEY', isActive: true });
            console.log('Initial "MONEY" unique code created.');
        }

        // Ensure global admin settings exist
        const adminSettings = await AdminSetting.findById('globalSettings');
        if (!adminSettings) {
            await AdminSetting.create({ _id: 'globalSettings' });
            console.log('Default admin settings created.');
        }
    })
    .catch(err => {
        console.error('MongoDB connection error (Vercel API):', err);
    });

// Utility for generating JWT token
const generateToken = (id, isAdmin = false) => {
    return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET, {
        expiresIn: '1h', // Token expires in 1 hour
    });
};

/* ------------------------------------------------------------- */
/* WEB APPLICATION API ENDPOINTS                                 */
/* ------------------------------------------------------------- */

// @route   POST /api/signup
// @desc    Register a new user
// @access  Public
app.post('/api/signup', async (req, res) => {
    const { fullName, email, password, telegramUsername, uniqueCode } = req.body;

    // Server-side validation
    const fieldErrors = {};
    if (!fullName || fullName.length < 3) fieldErrors.fullName = 'Full Name must be at least 3 characters.';
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fieldErrors.email = 'Please enter a valid email address.';
    if (!password || password.length < 6) fieldErrors.password = 'Password must be at least 6 characters.';
    if (!telegramUsername || !telegramUsername.startsWith('@')) fieldErrors.telegramUsername = 'Telegram Username must start with @.';
    if (!uniqueCode || uniqueCode.length !== 5) fieldErrors.uniqueCode = 'Unique Code must be 5 characters long.';

    if (Object.keys(fieldErrors).length > 0) {
        return res.status(400).json({ message: 'Validation Error', fieldErrors });
    }

    try {
        // Check if email or telegramUsername already exists
        let userExists = await User.findOne({ email });
        if (userExists) {
            fieldErrors.email = 'Email already registered.';
        }
        userExists = await User.findOne({ telegramUsername });
        if (userExists) {
            fieldErrors.telegramUsername = 'Telegram Username already registered.';
        }
        if (Object.keys(fieldErrors).length > 0) {
            return res.status(400).json({ message: 'Validation Error', fieldErrors });
        }

        // Validate unique code
        const code = await UniqueCode.findOne({ code: uniqueCode.toUpperCase(), isActive: true });
        if (!code) {
            fieldErrors.uniqueCode = 'Invalid or inactive unique code.';
            return res.status(400).json({ message: 'Validation Error', fieldErrors });
        }
        if (code.expiryDate && new Date() > code.expiryDate) {
            fieldErrors.uniqueCode = 'Unique code has expired.';
            return res.status(400).json({ message: 'Validation Error', fieldErrors });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Get default CPM from admin settings
        const adminSettings = await AdminSetting.findById('globalSettings');
        const defaultCPM = adminSettings ? adminSettings.defaultCPM : 5.00;

        const user = await User.create({
            fullName,
            email,
            password: hashedPassword,
            telegramUsername,
            cpmRate: defaultCPM,
            isAdmin: false, // Ensure new users are not admins
            isBlocked: false, // Ensure new users are not blocked
            // telegramChatId and apiKey are NOT explicitly set here, so default: null and sparse: true will apply correctly.
        });

        sendLog(`New User Registered: ${user.email} (${user.telegramUsername})`);
        res.status(201).json({ message: 'User registered successfully!' });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during signup.' });
    }
});

// @route   POST /api/login
// @desc    Authenticate user & get token
// @access  Public
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        if (user.isBlocked) {
            return res.status(403).json({ message: 'Your account has been blocked. Please contact support.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = generateToken(user._id, user.isAdmin);
        res.json({
            message: 'Login successful',
            token,
            userId: user._id,
            isAdmin: user.isAdmin,
            email: user.email // Optionally send email back
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// @route   GET /api/user-stats
// @desc    Get user dashboard statistics
// @access  Private (User)
app.get('/api/user-stats', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const todayIST = getStartOfISTDay(); // Start of today in IST

        // Calculate today's revenue
        const todayEarnings = await Earning.aggregate([
            { $match: { userId: user._id, date: todayIST } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const todayRevenue = todayEarnings.length > 0 ? todayEarnings[0].total : 0;

        res.json({
            currentBalance: user.balance,
            todayRevenue: todayRevenue,
            totalViews: user.totalViews,
            usdtAddress: user.usdtAddress,
            totalEarnings: user.balance, // For simplicity, total earnings is current balance
            theme: user.theme // Send user's theme setting
        });

    } catch (error) {
        console.error('Error fetching user stats:', error);
        res.status(500).json({ message: 'Failed to fetch user statistics.' });
    }
});

// @route   GET /api/user/api-key
// @desc    Generate and retrieve a one-time API key
// @access  Private (User)
app.get('/api/user/api-key', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate a new API key (longer for better uniqueness)
        const newApiKey = generateUniqueCode() + generateUniqueCode() + generateUniqueCode();
        // Store the key in cache with a 5-minute expiry
        // The userId is the value, newApiKey is the key
        apiKeyCache.set(newApiKey, user._id.toString());

        // Also update user's API key field in DB as a backup/reference
        user.apiKey = newApiKey;
        user.apiKeyGeneratedAt = new Date();
        await user.save();

        sendLog(`API Key Generated for User: ${user.email}`);
        res.json({ apiKey: newApiKey });
    } catch (error) {
        console.error('Error generating API key:', error);
        res.status(500).json({ message: 'Failed to generate API key.' });
    }
});

// @route   POST /api/user/payment
// @desc    Save/Update USDT BEP20 wallet address
// @access  Private (User)
app.post('/api/user/payment', protect, async (req, res) => {
    const { usdtAddress } = req.body;

    if (!usdtAddress || !isValidUsdtAddress(usdtAddress)) {
        return res.status(400).json({ message: 'Please provide a valid USDT BEP20 address.' });
    }

    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        user.usdtAddress = usdtAddress;
        await user.save();
        res.json({ message: 'USDT address saved successfully!' });
    } catch (error) {
        console.error('Error saving USDT address:', error);
        res.status(500).json({ message: 'Failed to save USDT address.' });
    }
});

// @route   POST /api/user/withdraw
// @desc    Submit a withdrawal request
// @access  Private (User)
app.post('/api/user/withdraw', protect, async (req, res) => {
    const { amount, usdtAddress } = req.body;

    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const adminSettings = await AdminSetting.findById('globalSettings');
        const minWithdrawal = adminSettings ? adminSettings.minWithdrawal : 100.00;

        if (amount < minWithdrawal) {
            return res.status(400).json({ message: `Minimum withdrawal amount is $${minWithdrawal}.` });
        }
        if (amount > user.balance) {
            return res.status(400).json({ message: 'Insufficient balance.' });
        }
        if (!user.usdtAddress || user.usdtAddress !== usdtAddress || !isValidUsdtAddress(usdtAddress)) {
            return res.status(400).json({ message: 'Provided USDT address does not match your saved address or is invalid. Please update your saved address.' });
        }

        const withdrawal = await Withdrawal.create({
            userId: user._id,
            amount,
            usdtAddress: user.usdtAddress,
            status: 'Pending',
        });

        // Deduct from user's balance immediately
        user.balance -= amount;
        await user.save();

        sendLog(`Withdrawal Request: User ${user.email} requested $${amount} to ${user.usdtAddress}`);
        res.status(201).json({ message: 'Withdrawal request submitted successfully!', withdrawal });

    } catch (error) {
        console.error('Error submitting withdrawal request:', error);
        res.status(500).json({ message: 'Failed to submit withdrawal request.' });
    }
});

// @route   GET /api/user/earnings-history
// @desc    Fetch last 10 days earning history
// @access  Private (User)
app.get('/api/user/earnings-history', protect, async (req, res) => {
    try {
        const earnings = await Earning.find({ userId: req.user._id })
            .sort({ date: -1 })
            .limit(10); // Last 10 days

        res.json({ earnings });
    } catch (error) {
        console.error('Error fetching earnings history:', error);
        res.status(500).json({ message: 'Failed to fetch earnings history.' });
    }
});

// @route   GET /api/user/recent-links
// @desc    Retrieve last 10 generated links for a user
// @access  Private (User)
app.get('/api/user/recent-links', protect, async (req, res) => {
    try {
        const links = await Link.find({ userId: req.user._id })
            .sort({ createdDate: -1 })
            .limit(10)
            .select('generatedLink viewCount createdDate _id'); // Select only necessary fields

        res.json({ links });
    } catch (error) {
        console.error('Error fetching recent links:', error);
        res.status(500).json({ message: 'Failed to fetch recent links.' });
    }
});

// @route   DELETE /api/user/links/:linkId
// @desc    Delete a user's link (set isActive to false)
// @access  Private (User)
app.delete('/api/user/links/:linkId', protect, async (req, res) => {
    try {
        const link = await Link.findOne({ _id: req.params.linkId, userId: req.user._id });

        if (!link) {
            return res.status(404).json({ message: 'Link not found or you are not authorized to delete it.' });
        }

        link.isActive = false; // Mark as inactive instead of deleting permanently
        await link.save();

        sendLog(`Link Deleted: User ${req.user.email} deactivated link ${link.uniqueId}`);
        res.json({ message: 'Link deleted successfully (marked inactive).' });
    } catch (error) {
        console.error('Error deleting link:', error);
        res.status(500).json({ message: 'Failed to delete link.' });
    }
});

// @route   PUT /api/user/settings/theme
// @desc    Update user's theme setting
// @access  Private (User)
app.put('/api/user/settings/theme', protect, async (req, res) => {
    const { theme } = req.body;
    if (!['light', 'dark'].includes(theme)) {
        return res.status(400).json({ message: 'Invalid theme provided. Must be "light" or "dark".' });
    }
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        user.theme = theme;
        await user.save();
        res.json({ message: 'Theme updated successfully!', theme: user.theme });
    } catch (error) {
        console.error('Error updating user theme:', error);
        res.status(500).json({ message: 'Failed to update theme.' });
    }
});

// @route   PUT /api/user/settings/profile
// @desc    Update user's profile information (name, email, telegram username)
// @access  Private (User)
app.put('/api/user/settings/profile', protect, async (req, res) => {
    const { fullName, email, telegramUsername } = req.body;

    // Server-side validation
    const fieldErrors = {};
    if (fullName && fullName.length < 3) fieldErrors.fullName = 'Full Name must be at least 3 characters.';
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fieldErrors.email = 'Please enter a valid email address.';
    if (telegramUsername && !telegramUsername.startsWith('@')) fieldErrors.telegramUsername = 'Telegram Username must start with @.';

    if (Object.keys(fieldErrors).length > 0) {
        return res.status(400).json({ message: 'Validation Error', fieldErrors });
    }

    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Check for unique fields if they are being changed
        if (email && email !== user.email) {
            const existingEmailUser = await User.findOne({ email, _id: { $ne: user._id } });
            if (existingEmailUser) {
                return res.status(400).json({ message: 'Email already in use.', fieldErrors: { email: 'This email is already registered.' } });
            }
            user.email = email;
        }
        if (telegramUsername && telegramUsername !== user.telegramUsername) {
            const existingTelegramUser = await User.findOne({ telegramUsername, _id: { $ne: user._id } });
            if (existingTelegramUser) {
                return res.status(400).json({ message: 'Telegram username already in use.', fieldErrors: { telegramUsername: 'This Telegram username is already registered.' } });
            }
            user.telegramUsername = telegramUsername;
        }

        user.fullName = fullName || user.fullName; // Update if provided
        await user.save();
        res.json({ message: 'Profile updated successfully!', user: { fullName: user.fullName, email: user.email, telegramUsername: user.telegramUsername } });

    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).json({ message: 'Failed to update profile.' });
    }
});


/* ------------------------------------------------------------- */
/* ADMIN API ENDPOINTS                                           */
/* ------------------------------------------------------------- */

// @route   POST /api/admin/login
// @desc    Authenticate admin
// @access  Public (for initial admin login)
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body; // Using 'username' for admin login form

    // For simplicity, using hardcoded admin email and password.
    // In production, this should be managed through proper admin user accounts.
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@linkearn.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

    try {
        const adminUser = await User.findOne({ email: adminEmail, isAdmin: true });

        if (!adminUser) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        // Validate username (email in this case)
        if (username !== adminEmail) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const isMatch = await bcrypt.compare(password, adminUser.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const token = generateToken(adminUser._id, true);
        res.json({
            message: 'Admin login successful',
            token,
            userId: adminUser._id,
            isAdmin: true
        });

    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ message: 'Server error during admin login.' });
    }
});


// @route   GET /api/admin/dashboard
// @desc    Get admin dashboard aggregated metrics
// @access  Private (Admin)
app.get('/api/admin/dashboard', protect, adminProtect, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ isAdmin: false }); // Only count non-admin users
        const totalLinks = await Link.countDocuments({});
        const pendingWithdrawalsCount = await Withdrawal.countDocuments({ status: 'Pending' });

        const todayIST = getStartOfISTDay();
        const startOfMonthIST = DateTime.now().setZone('Asia/Kolkata').startOf('month').toJSDate();

        // Daily Revenue
        const dailyRevenueResult = await Earning.aggregate([
            { $match: { date: todayIST } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const dailyRevenue = dailyRevenueResult.length > 0 ? dailyRevenueResult[0].total : 0;

        // Monthly Revenue
        const monthlyRevenueResult = await Earning.aggregate([
            { $match: { date: { $gte: startOfMonthIST } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const monthlyRevenue = monthlyRevenueResult.length > 0 ? monthlyRevenueResult[0].total : 0;

        res.json({
            totalUsers,
            dailyRevenue,
            monthlyRevenue,
            totalLinks,
            pendingWithdrawalsCount
        });
    } catch (error) {
        console.error('Error fetching admin dashboard data:', error);
        res.status(500).json({ message: 'Failed to fetch dashboard data.' });
    }
});

// @route   GET /api/admin/users
// @desc    Get all users (with optional search)
// @access  Private (Admin)
app.get('/api/admin/users', protect, adminProtect, async (req, res) => {
    const { search } = req.query;
    let query = { isAdmin: false }; // Exclude admin user from general user list
    if (search) {
        query = {
            ...query,
            $or: [
                { email: { $regex: search, $options: 'i' } },
                { telegramUsername: { $regex: search, $options: 'i' } },
                { fullName: { $regex: search, $options: 'i' } } // Allow searching by full name
            ]
        };
    }
    try {
        const users = await User.find(query).select('-password'); // Exclude password
        res.json({ users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Failed to fetch users.' });
    }
});

// @route   PUT /api/admin/users/:userId
// @desc    Edit individual user earnings, CPM rates, etc.
// @access  Private (Admin)
app.put('/api/admin/users/:userId', protect, adminProtect, async (req, res) => {
    const { fullName, email, telegramUsername, balance, cpmRate } = req.body;

    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (user.isAdmin) {
            return res.status(403).json({ message: 'Cannot edit admin account via this endpoint.' });
        }

        // Validate and update fields
        if (fullName) user.fullName = fullName;
        if (email) {
            if (email !== user.email) {
                const existingUserWithEmail = await User.findOne({ email, _id: { $ne: user._id } });
                if (existingUserWithEmail) {
                    return res.status(400).json({ message: 'Email already taken by another user.' });
                }
            }
            user.email = email;
        }
        if (telegramUsername) {
            if (telegramUsername !== user.telegramUsername) {
                const existingUserWithTg = await User.findOne({ telegramUsername, _id: { $ne: user._id } });
                if (existingUserWithTg) {
                    return res.status(400).json({ message: 'Telegram Username already taken by another user.' });
                }
            }
            user.telegramUsername = telegramUsername;
        }

        user.balance = typeof balance === 'number' ? balance : user.balance;
        user.cpmRate = typeof cpmRate === 'number' ? cpmRate : user.cpmRate;

        await user.save();
        sendLog(`Admin Edited User: ${user.email} (ID: ${user._id})`);
        res.json({ message: 'User updated successfully!', user });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ message: 'Failed to update user.' });
    }
});

// @route   PUT /api/admin/users/:userId/block
// @desc    Block/unblock a user
// @access  Private (Admin)
app.put('/api/admin/users/:userId/block', protect, adminProtect, async (req, res) => {
    const { isBlocked } = req.body;
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (user.isAdmin) {
             return res.status(403).json({ message: 'Cannot block an admin account.' });
        }
        user.isBlocked = isBlocked;
        await user.save();
        sendLog(`Admin ${isBlocked ? 'Blocked' : 'Unblocked'} User: ${user.email} (ID: ${user._id})`);
        res.json({ message: `User ${isBlocked ? 'blocked' : 'unblocked'} successfully!`, user });
    } catch (error) {
        console.error('Error blocking/unblocking user:', error);
        res.status(500).json({ message: 'Failed to update user block status.' });
    }
});


// @route   GET /api/admin/withdrawals
// @desc    Get all pending withdrawal requests
// @access  Private (Admin)
app.get('/api/admin/withdrawals', protect, adminProtect, async (req, res) => {
    try {
        // Populate user email for display
        const withdrawals = await Withdrawal.find({})
            .populate('userId', 'email telegramUsername') // Populate userId to get email and telegramUsername
            .sort({ requestDate: -1 });

        // Transform data to include user email directly for frontend
        const formattedWithdrawals = withdrawals.map(w => ({
            ...w.toObject(),
            userEmail: w.userId ? w.userId.email : 'N/A',
            telegramUsername: w.userId ? w.userId.telegramUsername : 'N/A'
        }));

        res.json({ withdrawals: formattedWithdrawals });
    } catch (error) {
        console.error('Error fetching withdrawals:', error);
        res.status(500).json({ message: 'Failed to fetch withdrawal requests.' });
    }
});

// @route   PUT /api/admin/withdrawals/:requestId
// @desc    Approve or reject a withdrawal request
// @access  Private (Admin)
app.put('/api/admin/withdrawals/:requestId', protect, adminProtect, async (req, res) => {
    const { status } = req.body; // 'Approved' or 'Rejected'

    try {
        const withdrawal = await Withdrawal.findById(req.params.requestId);
        if (!withdrawal) {
            return res.status(404).json({ message: 'Withdrawal request not found.' });
        }
        if (withdrawal.status !== 'Pending') {
            return res.status(400).json({ message: 'Withdrawal request already processed.' });
        }

        withdrawal.status = status;
        withdrawal.processedDate = new Date();
        await withdrawal.save();

        // If rejected, refund balance to user
        if (status === 'Rejected') {
            const user = await User.findById(withdrawal.userId);
            if (user) {
                user.balance += withdrawal.amount;
                await user.save();
                sendLog(`Withdrawal Rejected & Refunded: User ${user.email}, Amount $${withdrawal.amount}`);
            }
        }
        sendLog(`Admin Processed Withdrawal: Request ID ${withdrawal._id}, Status: ${status}`);
        res.json({ message: `Withdrawal request ${status.toLowerCase()}!`, withdrawal });
    } catch (error) {
        console.error('Error processing withdrawal:', error);
        res.status(500).json({ message: 'Failed to process withdrawal request.' });
    }
});

// @route   POST /api/admin/unique-codes/generate
// @desc    Generate new unique codes
// @access  Private (Admin)
app.post('/api/admin/unique-codes/generate', protect, adminProtect, async (req, res) => {
    const { count } = req.body;
    if (count < 1 || count > 5) {
        return res.status(400).json({ message: 'Can only generate between 1 and 5 codes at once.' });
    }
    try {
        const generatedCodes = [];
        for (let i = 0; i < count; i++) {
            let newCode;
            let codeExists = true;
            while(codeExists) { // Ensure uniqueness
                newCode = generateUniqueCode();
                const existing = await UniqueCode.findOne({ code: newCode });
                if (!existing) codeExists = false;
            }
            const code = await UniqueCode.create({ code: newCode, isActive: true });
            generatedCodes.push(code.code);
        }
        sendLog(`Admin Generated ${count} Unique Codes`);
        res.status(201).json({ message: 'Codes generated successfully!', codes: generatedCodes });
    } catch (error) {
        console.error('Error generating unique codes:', error);
        res.status(500).json({ message: 'Failed to generate unique codes.' });
    }
});

// @route   GET /api/admin/unique-codes
// @desc    Get all unique codes
// @access  Private (Admin)
app.get('/api/admin/unique-codes', protect, adminProtect, async (req, res) => {
    try {
        const codes = await UniqueCode.find({}).sort({ createdDate: -1 });
        res.json({ codes });
    } catch (error) {
        console.error('Error fetching unique codes:', error);
        res.status(500).json({ message: 'Failed to fetch unique codes.' });
    }
});

// @route   PUT /api/admin/unique-codes/:codeId/status
// @desc    Activate/Deactivate a unique code
// @access  Private (Admin)
app.put('/api/admin/unique-codes/:codeId/status', protect, adminProtect, async (req, res) => {
    const { isActive } = req.body;
    try {
        const code = await UniqueCode.findById(req.params.codeId);
        if (!code) {
            return res.status(404).json({ message: 'Unique code not found.' });
        }
        code.isActive = isActive;
        await code.save();
        sendLog(`Admin ${isActive ? 'Activated' : 'Deactivated'} Unique Code: ${code.code}`);
        res.json({ message: `Unique code ${isActive ? 'activated' : 'deactivated'}!`, code });
    } catch (error) {
        console.error('Error updating unique code status:', error);
        res.status(500).json({ message: 'Failed to update unique code status.' });
    }
});

// @route   DELETE /api/admin/unique-codes/:codeId
// @desc    Delete a unique code
// @access  Private (Admin)
app.delete('/api/admin/unique-codes/:codeId', protect, adminProtect, async (req, res) => {
    try {
        const code = await UniqueCode.findById(req.params.codeId);
        if (!code) {
            return res.status(404).json({ message: 'Unique code not found.' });
        }
        await UniqueCode.deleteOne({ _id: req.params.codeId });
        sendLog(`Admin Deleted Unique Code: ${code.code}`);
        res.json({ message: 'Unique code deleted successfully!' });
    } catch (error) {
        console.error('Error deleting unique code:', error);
        res.status(500).json({ message: 'Failed to delete unique code.' });
    }
});


// @route   GET /api/admin/settings
// @desc    Get global system settings
// @access  Private (Admin)
app.get('/api/admin/settings', protect, adminProtect, async (req, res) => {
    try {
        const settings = await AdminSetting.findById('globalSettings');
        if (!settings) {
            // Should not happen as we create it on startup
            return res.status(404).json({ message: 'Admin settings not found.' });
        }
        res.json({ minWithdrawal: settings.minWithdrawal, defaultCPM: settings.defaultCPM });
    } catch (error) {
        console.error('Error fetching admin settings:', error);
        res.status(500).json({ message: 'Failed to fetch admin settings.' });
    }
});

// @route   PUT /api/admin/settings
// @desc    Update global system settings
// @access  Private (Admin)
app.put('/api/admin/settings', protect, adminProtect, async (req, res) => {
    const { minWithdrawal, defaultCPM } = req.body;
    try {
        let settings = await AdminSetting.findById('globalSettings');
        if (!settings) {
            settings = await AdminSetting.create({ _id: 'globalSettings' });
        }
        settings.minWithdrawal = typeof minWithdrawal === 'number' ? minWithdrawal : settings.minWithdrawal;
        settings.defaultCPM = typeof defaultCPM === 'number' ? defaultCPM : settings.defaultCPM;
        settings.updatedAt = Date.now(); // Update timestamp
        await settings.save();
        sendLog(`Admin Updated System Settings: Min Withdrawal $${settings.minWithdrawal}, Default CPM ${settings.defaultCPM}`);
        res.json({ message: 'System settings updated successfully!', settings });
    } catch (error) {
        console.error('Error updating admin settings:', error);
        res.status(500).json({ message: 'Failed to update admin settings.' });
    }
});


/* ------------------------------------------------------------- */
/* TELEGRAM MINI APP API ENDPOINTS (CALLED BY MINI APP)          */
/* NOTE: The bot itself runs on Heroku, but Mini Apps call these API endpoints. */
/* ------------------------------------------------------------- */

// @route   POST /api/count-view
// @desc    Record a completed view from Telegram Mini App
// @access  Public (via initData validation)
app.post('/api/count-view', validateInitData, async (req, res) => {
    const { uniqueId } = req.body;
    const viewerTelegramId = req.viewerTelegramId; // From validateInitData middleware

    try {
        const link = await Link.findOne({ uniqueId, isActive: true });
        if (!link) {
            console.log(`View attempt for non-existent or inactive link: ${uniqueId}`);
            return res.status(404).json({ message: 'Link not found or is inactive.' });
        }

        // Check if this viewer has already viewed this link
        const alreadyViewed = link.viewers.some(v => v.viewerTelegramId === viewerTelegramId);
        if (alreadyViewed) {
            console.log(`View attempt: Viewer ${viewerTelegramId} already viewed link ${uniqueId}`);
            // Still deliver media if they already viewed, but don't count again
            // Respond with success so Mini App proceeds to deliver media
            return res.json({ message: 'View already counted for this user. Media will be delivered.' });
        }

        const user = await User.findById(link.userId);
        if (!user || user.isBlocked) {
            console.log(`View attempt: User for link ${uniqueId} not found or is blocked.`);
            return res.status(404).json({ message: 'Associated user account not found or is blocked.' });
        }

        // Increment view count for the link
        link.viewCount += 1;
        link.viewers.push({ viewerTelegramId }); // Add viewer to prevent re-counting
        await link.save();

        // Increment total views for the user
        user.totalViews += 1;

        // Calculate earning for this view
        const earningPerView = user.cpmRate / 1000;
        user.balance += earningPerView;
        await user.save();

        // Update daily earnings for the user in IST
        const todayIST = getStartOfISTDay();
        let dailyEarning = await Earning.findOne({ userId: user._id, date: todayIST });

        if (dailyEarning) {
            dailyEarning.amount += earningPerView;
            dailyEarning.views += 1;
            await dailyEarning.save();
        } else {
            await Earning.create({
                userId: user._id,
                amount: earningPerView,
                date: todayIST,
                views: 1
            });
        }

        sendLog(`View Counted & Earned: User ${user.email}, Link ${uniqueId}, Viewer ${viewerTelegramId}, Amount $${earningPerView.toFixed(4)}`);
        res.json({ message: 'View counted successfully! Media will be delivered.' });

    } catch (error) {
        console.error('Error counting view:', error);
        res.status(500).json({ message: 'Failed to count view.' });
    }
});

// @route   GET /api/media/:uniqueId
// @desc    Retrieve media file_id for delivery
// @access  Public (called by Mini App after ad completion, or bot based on Mini App signal)
app.get('/api/media/:uniqueId', async (req, res) => {
    try {
        const uniqueId = req.params.uniqueId;
        const link = await Link.findOne({ uniqueId, isActive: true }).select('mediaFileId');

        if (!link) {
            return res.status(404).json({ message: 'Media not found or is inactive.' });
        }
        res.json({ mediaFileId: link.mediaFileId });
    } catch (error) {
        console.error('Error fetching media file ID:', error);
        res.status(500).json({ message: 'Failed to fetch media ID.' });
    }
});


// Public endpoint for handling dynamic links/redirections for content monetization
// @route   GET /:uniqueId
// @desc    Handle short link redirection and view counting
// @access  Public
app.get('/:uniqueId', async (req, res) => {
    try {
        const { uniqueId } = req.params;
        const link = await Link.findOne({ uniqueId, isActive: true });

        if (!link) {
            return res.status(404).send('Link not found or inactive.');
        }

        // Redirect to the original media URL.
        // The view counting logic is now primarily handled by the Telegram Mini App's call to /api/count-view
        // This route is purely for redirection if accessed directly via browser.
        res.redirect(link.originalUrl);

    } catch (error) {
        console.error('Error handling link redirection:', error);
        res.status(500).send('Internal server error during redirection.');
    }
});


// Fallback for non-matching API routes (e.g., if a route doesn't exist)
app.use('/api/*', (req, res) => {
    res.status(404).json({ message: 'API Endpoint not found.' });
});

// Export the Express app for Vercel Serverless Functions
module.exports = app;

// IMPORTANT: Do NOT include bot.launch() here if your bot runs on Heroku.
// Vercel serverless functions are stateless and short-lived;
// a long-running bot process will cause timeouts and errors.
// If your bot runs on Heroku, ensure its bot.js or server.js starts the bot there.
// If you intend for Vercel to handle bot webhooks, that's a different setup.
// For now, assuming bot is entirely on Heroku.
