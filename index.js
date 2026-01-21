const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize services
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

const resend = new Resend(process.env.RESEND_API_KEY);

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'mzone_secret_2024';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://tgzoro12.github.io/mzone';

// Middleware
app.use(cors({
    origin: ['https://tgzoro12.github.io', 'http://localhost:3000', 'http://127.0.0.1:5500'],
    credentials: true
}));
app.use(express.json());

// Helper: Generate 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper: Validate password (alphanumeric, min 10 chars)
function validatePassword(password) {
    if (password.length < 10) {
        return { valid: false, message: 'Password must be at least 10 characters' };
    }
    if (!/[a-zA-Z]/.test(password)) {
        return { valid: false, message: 'Password must contain letters' };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, message: 'Password must contain numbers' };
    }
    if (/^[a-zA-Z]+$/.test(password) || /^[0-9]+$/.test(password)) {
        return { valid: false, message: 'Password must be alphanumeric (letters AND numbers)' };
    }
    return { valid: true };
}

// Helper: Verify JWT token
function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// Health check
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        message: 'MZone API Server Running',
        timestamp: new Date().toISOString()
    });
});

// ==================== AUTH ROUTES ====================

// REGISTER
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password, fullName } = req.body;

        // Validate input
        if (!email || !password || !fullName) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email, password, and full name are required' 
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email format' 
            });
        }

        // Validate password
        const passwordCheck = validatePassword(password);
        if (!passwordCheck.valid) {
            return res.status(400).json({ 
                success: false, 
                message: passwordCheck.message 
            });
        }

        // Check if user already exists
        const { data: existingUser } = await supabase
            .from('profiles')
            .select('email')
            .eq('email', email.toLowerCase())
            .single();

        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email already registered' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Generate OTP
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Create user in database
        const { data: newUser, error: insertError } = await supabase
            .from('profiles')
            .insert({
                id: crypto.randomUUID(),
                email: email.toLowerCase(),
                full_name: fullName,
                password_hash: hashedPassword,
                email_verified: false,
                otp_code: otp,
                otp_expires_at: otpExpires.toISOString(),
                is_subscribed: false,
                created_at: new Date().toISOString()
            })
            .select()
            .single();

        if (insertError) {
            console.error('Insert error:', insertError);
            return res.status(500).json({ 
                success: false, 
                message: 'Failed to create account' 
            });
        }

        // Send OTP email
        try {
            await resend.emails.send({
                from: 'MZone <onboarding@resend.dev>',
                to: email,
                subject: 'Verify your MZone account - OTP Code',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #6366f1; text-align: center;">🎬 MZone</h1>
                        <h2 style="text-align: center;">Verify Your Email</h2>
                        <p>Hello ${fullName},</p>
                        <p>Your verification code is:</p>
                        <div style="background: #f3f4f6; padding: 20px; text-align: center; border-radius: 10px; margin: 20px 0;">
                            <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #1a1a2e;">${otp}</span>
                        </div>
                        <p>This code expires in <strong>10 minutes</strong>.</p>
                        <p>If you didn't create an account, please ignore this email.</p>
                        <hr style="margin: 20px 0; border: none; border-top: 1px solid #e5e7eb;">
                        <p style="color: #666; font-size: 12px; text-align: center;">© 2024 MZone Premium</p>
                    </div>
                `
            });
        } catch (emailError) {
            console.error('Email error:', emailError);
            // Continue even if email fails - user can request new OTP
        }

        res.json({
            success: true,
            message: 'Account created! Check your email for verification code.',
            email: email.toLowerCase()
        });

    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error. Please try again.' 
        });
    }
});

// VERIFY OTP
app.post('/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and OTP are required' 
            });
        }

        // Get user
        const { data: user, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('email', email.toLowerCase())
            .single();

        if (error || !user) {
            return res.status(400).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Check if already verified
        if (user.email_verified) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email already verified. Please login.' 
            });
        }

        // Check OTP
        if (user.otp_code !== otp) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid OTP code' 
            });
        }

        // Check if OTP expired
        if (new Date(user.otp_expires_at) < new Date()) {
            return res.status(400).json({ 
                success: false, 
                message: 'OTP expired. Please request a new one.' 
            });
        }

        // Update user as verified
        await supabase
            .from('profiles')
            .update({ 
                email_verified: true,
                otp_code: null,
                otp_expires_at: null,
                updated_at: new Date().toISOString()
            })
            .eq('email', email.toLowerCase());

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email,
                fullName: user.full_name 
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'Email verified successfully!',
            token,
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                emailVerified: true,
                isSubscribed: user.is_subscribed
            }
        });

    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error. Please try again.' 
        });
    }
});

// RESEND OTP
app.post('/auth/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email is required' 
            });
        }

        // Get user
        const { data: user, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('email', email.toLowerCase())
            .single();

        if (error || !user) {
            return res.status(400).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        if (user.email_verified) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email already verified' 
            });
        }

        // Generate new OTP
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        // Update user with new OTP
        await supabase
            .from('profiles')
            .update({ 
                otp_code: otp,
                otp_expires_at: otpExpires.toISOString()
            })
            .eq('email', email.toLowerCase());

        // Send email
        await resend.emails.send({
            from: 'MZone <onboarding@resend.dev>',
            to: email,
            subject: 'New OTP Code - MZone',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
                    <h1 style="color: #6366f1; text-align: center;">🎬 MZone</h1>
                    <h2 style="text-align: center;">Your New OTP Code</h2>
                    <div style="background: #f3f4f6; padding: 20px; text-align: center; border-radius: 10px; margin: 20px 0;">
                        <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #1a1a2e;">${otp}</span>
                    </div>
                    <p>This code expires in <strong>10 minutes</strong>.</p>
                </div>
            `
        });

        res.json({
            success: true,
            message: 'New OTP sent to your email'
        });

    } catch (error) {
        console.error('Resend OTP error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error. Please try again.' 
        });
    }
});

// LOGIN
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }

        // Get user
        const { data: user, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('email', email.toLowerCase())
            .single();

        if (error || !user) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        // Check if email verified
        if (!user.email_verified) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please verify your email first',
                needsVerification: true,
                email: user.email
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email,
                fullName: user.full_name 
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'Login successful!',
            token,
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                emailVerified: user.email_verified,
                isSubscribed: user.is_subscribed,
                subscriptionExpires: user.subscription_expires_at
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error. Please try again.' 
        });
    }
});

// GET USER PROFILE (Protected)
app.get('/auth/me', verifyToken, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (error || !user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Check if subscription expired
        let isSubscribed = user.is_subscribed;
        if (user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date()) {
            isSubscribed = false;
            // Update database
            await supabase
                .from('profiles')
                .update({ is_subscribed: false })
                .eq('id', user.id);
        }

        res.json({
            success: true,
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                emailVerified: user.email_verified,
                isSubscribed: isSubscribed,
                subscriptionExpires: user.subscription_expires_at
            }
        });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// ==================== PAYMENT ROUTES ====================

// Initialize payment
app.post('/payment/initialize', verifyToken, async (req, res) => {
    try {
        const { plan } = req.body;
        
        // Get user
        const { data: user } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        if (!user.email_verified) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please verify your email first' 
            });
        }

        // Plan pricing (in kobo)
        const plans = {
            monthly: { amount: 1600000, name: 'Monthly Plan' },
            yearly: { amount: 15360000, name: 'Yearly Plan' }
        };

        const selectedPlan = plans[plan] || plans.monthly;

        const response = await axios.post(
            'https://api.paystack.co/transaction/initialize',
            {
                email: user.email,
                amount: selectedPlan.amount,
                callback_url: `${FRONTEND_URL}/dashboard.html?payment=success`,
                metadata: {
                    user_id: user.id,
                    plan: plan,
                    custom_fields: [
                        {
                            display_name: "Customer Name",
                            variable_name: "customer_name",
                            value: user.full_name
                        },
                        {
                            display_name: "Plan",
                            variable_name: "plan",
                            value: selectedPlan.name
                        }
                    ]
                }
            },
            {
                headers: {
                    'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        res.json({
            success: true,
            authorization_url: response.data.data.authorization_url,
            reference: response.data.data.reference
        });

    } catch (error) {
        console.error('Payment init error:', error.response?.data || error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to initialize payment' 
        });
    }
});

// Verify payment
app.get('/payment/verify/:reference', verifyToken, async (req, res) => {
    try {
        const { reference } = req.params;

        const response = await axios.get(
            `https://api.paystack.co/transaction/verify/${reference}`,
            {
                headers: {
                    'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`
                }
            }
        );

        const data = response.data.data;

        if (data.status === 'success') {
            // Calculate subscription expiry (30 days for monthly, 365 for yearly)
            const plan = data.metadata?.plan || 'monthly';
            const days = plan === 'yearly' ? 365 : 30;
            const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

            // Update user subscription
            await supabase
                .from('profiles')
                .update({
                    is_subscribed: true,
                    subscription_ref: reference,
                    subscription_date: new Date().toISOString(),
                    subscription_expires_at: expiresAt.toISOString(),
                    updated_at: new Date().toISOString()
                })
                .eq('id', req.user.id);

            res.json({
                success: true,
                message: 'Payment verified! Subscription activated.',
                subscription: {
                    active: true,
                    expiresAt: expiresAt.toISOString(),
                    plan: plan
                }
            });
        } else {
            res.status(400).json({
                success: false,
                message: 'Payment not successful',
                status: data.status
            });
        }

    } catch (error) {
        console.error('Verify payment error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to verify payment' 
        });
    }
});

// Paystack Webhook
app.post('/payment/webhook', async (req, res) => {
    try {
        const event = req.body;

        if (event.event === 'charge.success') {
            const data = event.data;
            const userId = data.metadata?.user_id;

            if (userId) {
                const plan = data.metadata?.plan || 'monthly';
                const days = plan === 'yearly' ? 365 : 30;
                const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

                await supabase
                    .from('profiles')
                    .update({
                        is_subscribed: true,
                        subscription_ref: data.reference,
                        subscription_date: new Date().toISOString(),
                        subscription_expires_at: expiresAt.toISOString()
                    })
                    .eq('id', userId);
            }
        }

        res.sendStatus(200);
    } catch (error) {
        console.error('Webhook error:', error);
        res.sendStatus(500);
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`MZone API Server running on port ${PORT}`);
});
