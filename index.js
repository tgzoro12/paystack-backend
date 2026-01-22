const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'mzone_secret_2024';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://tgzoro12.github.io/mzone';

// SUBSCRIPTION PLANS
const PLANS = {
    standard_monthly: {
        name: 'Standard Monthly',
        amount: 1600000, // ₦16,000 in kobo
        duration: 30 // days
    },
    standard_yearly: {
        name: 'Standard Yearly',
        amount: 14500000, // ₦145,000 in kobo
        duration: 365 // days
    },
    pro_monthly: {
        name: 'Pro Monthly',
        amount: 2200000, // ₦22,000 in kobo
        duration: 30 // days
    },
    pro_yearly: {
        name: 'Pro Yearly',
        amount: 22000000, // ₦220,000 in kobo
        duration: 365 // days
    }
};

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function validatePassword(password) {
    if (!password || password.length < 10) return { valid: false, message: 'Password must be at least 10 characters' };
    if (!/[a-zA-Z]/.test(password)) return { valid: false, message: 'Password must contain letters' };
    if (!/[0-9]/.test(password)) return { valid: false, message: 'Password must contain numbers' };
    return { valid: true };
}

function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token provided' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

app.get('/', (req, res) => {
    res.json({ status: 'online', message: 'MZone API Running', plans: Object.keys(PLANS) });
});

// GET PLANS
app.get('/plans', (req, res) => {
    const planList = Object.entries(PLANS).map(([key, value]) => ({
        id: key,
        name: value.name,
        amount: value.amount / 100, // Convert to Naira
        duration: value.duration
    }));
    res.json({ success: true, plans: planList });
});

// REGISTER
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password, fullName } = req.body;
        if (!email || !password || !fullName) {
            return res.status(400).json({ success: false, message: 'All fields required' });
        }
        const passwordCheck = validatePassword(password);
        if (!passwordCheck.valid) {
            return res.status(400).json({ success: false, message: passwordCheck.message });
        }
        const { data: existing } = await supabase.from('profiles').select('email').eq('email', email.toLowerCase()).single();
        if (existing) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
        const { error } = await supabase.from('profiles').insert({
            email: email.toLowerCase(),
            password_hash: hashedPassword,
            full_name: fullName,
            otp_code: otp,
            otp_expires_at: otpExpires.toISOString(),
            email_verified: false,
            is_subscribed: false
        });
        if (error) {
            console.error('DB Error:', error);
            return res.status(500).json({ success: false, message: 'Failed to create account' });
        }
        try {
            await resend.emails.send({
                from: 'MZone <onboarding@resend.dev>',
                to: email,
                subject: 'Your MZone Verification Code',
                html: `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;background:#0a0a0f;color:#fff;border-radius:10px;"><h1 style="color:#8b5cf6;text-align:center;">🎬 MZone</h1><p>Hello ${fullName},</p><p>Your verification code is:</p><div style="background:#1a1a2e;padding:20px;text-align:center;border-radius:10px;margin:20px 0;"><span style="font-size:32px;font-weight:bold;letter-spacing:5px;color:#8b5cf6;">${otp}</span></div><p>Code expires in 10 minutes.</p></div>`
            });
        } catch (e) { console.error('Email error:', e); }
        res.json({ success: true, message: 'Account created! Check email for OTP.', email: email.toLowerCase() });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// VERIFY OTP
app.post('/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ success: false, message: 'Email and OTP required' });
        const { data: user } = await supabase.from('profiles').select('*').eq('email', email.toLowerCase()).single();
        if (!user) return res.status(400).json({ success: false, message: 'User not found' });
        if (user.email_verified) return res.status(400).json({ success: false, message: 'Already verified' });
        if (user.otp_code !== otp) return res.status(400).json({ success: false, message: 'Invalid OTP' });
        if (new Date(user.otp_expires_at) < new Date()) return res.status(400).json({ success: false, message: 'OTP expired' });
        await supabase.from('profiles').update({ email_verified: true, otp_code: null }).eq('email', email.toLowerCase());
        const token = jwt.sign({ id: user.id, email: user.email, fullName: user.full_name }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, message: 'Email verified!', token, user: { id: user.id, email: user.email, fullName: user.full_name, emailVerified: true, isSubscribed: user.is_subscribed } });
    } catch (error) {
        console.error('Verify error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// RESEND OTP
app.post('/auth/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const { data: user } = await supabase.from('profiles').select('*').eq('email', email.toLowerCase()).single();
        if (!user) return res.status(400).json({ success: false, message: 'User not found' });
        if (user.email_verified) return res.status(400).json({ success: false, message: 'Already verified' });
        const otp = generateOTP();
        await supabase.from('profiles').update({ otp_code: otp, otp_expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString() }).eq('email', email.toLowerCase());
        await resend.emails.send({
            from: 'MZone <onboarding@resend.dev>',
            to: email,
            subject: 'New MZone OTP Code',
            html: `<div style="font-family:Arial;padding:20px;background:#0a0a0f;color:#fff;border-radius:10px;"><h1 style="color:#8b5cf6;">🎬 MZone</h1><p>Your new code:</p><div style="background:#1a1a2e;padding:20px;text-align:center;border-radius:10px;"><span style="font-size:32px;font-weight:bold;color:#8b5cf6;">${otp}</span></div></div>`
        });
        res.json({ success: true, message: 'New OTP sent!' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// LOGIN
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
        const { data: user } = await supabase.from('profiles').select('*').eq('email', email.toLowerCase()).single();
        if (!user) return res.status(400).json({ success: false, message: 'Invalid credentials' });
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(400).json({ success: false, message: 'Invalid credentials' });
        if (!user.email_verified) return res.status(400).json({ success: false, message: 'Please verify email first', needsVerification: true, email: user.email });
        const token = jwt.sign({ id: user.id, email: user.email, fullName: user.full_name }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, user: { id: user.id, email: user.email, fullName: user.full_name, emailVerified: true, isSubscribed: user.is_subscribed, subscriptionPlan: user.subscription_plan, subscriptionExpires: user.subscription_expires_at } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// GET ME
app.get('/auth/me', verifyToken, async (req, res) => {
    try {
        const { data: user } = await supabase.from('profiles').select('*').eq('id', req.user.id).single();
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        let isSubscribed = user.is_subscribed;
        if (user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date()) {
            isSubscribed = false;
            await supabase.from('profiles').update({ is_subscribed: false }).eq('id', user.id);
        }
        res.json({ success: true, user: { id: user.id, email: user.email, fullName: user.full_name, emailVerified: user.email_verified, isSubscribed, subscriptionPlan: user.subscription_plan, subscriptionExpires: user.subscription_expires_at } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// INIT PAYMENT WITH PLAN
app.post('/payment/initialize', verifyToken, async (req, res) => {
    try {
        const { plan } = req.body;
        
        // Validate plan
        if (!plan || !PLANS[plan]) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid plan. Available plans: ' + Object.keys(PLANS).join(', ') 
            });
        }
        
        const selectedPlan = PLANS[plan];
        
        const { data: user } = await supabase.from('profiles').select('*').eq('id', req.user.id).single();
        if (!user || !user.email_verified) return res.status(400).json({ success: false, message: 'Verify email first' });
        
        const response = await axios.post('https://api.paystack.co/transaction/initialize', {
            email: user.email,
            amount: selectedPlan.amount,
            callback_url: `${FRONTEND_URL}/dashboard.html?payment=success`,
            metadata: { 
                user_id: user.id, 
                plan: plan,
                plan_name: selectedPlan.name,
                duration: selectedPlan.duration
            }
        }, { headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' } });
        
        res.json({ 
            success: true, 
            authorization_url: response.data.data.authorization_url, 
            reference: response.data.data.reference,
            plan: selectedPlan.name,
            amount: selectedPlan.amount / 100
        });
    } catch (error) {
        console.error('Payment init error:', error.response?.data || error);
        res.status(500).json({ success: false, message: 'Payment init failed' });
    }
});

// VERIFY PAYMENT
app.get('/payment/verify/:reference', verifyToken, async (req, res) => {
    try {
        const response = await axios.get(`https://api.paystack.co/transaction/verify/${req.params.reference}`, { headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}` } });
        
        if (response.data.data.status === 'success') {
            const metadata = response.data.data.metadata;
            const plan = metadata?.plan || 'standard_monthly';
            const duration = PLANS[plan]?.duration || 30;
            
            const expires = new Date(Date.now() + duration * 24 * 60 * 60 * 1000);
            
            await supabase.from('profiles').update({ 
                is_subscribed: true, 
                subscription_ref: req.params.reference, 
                subscription_plan: plan,
                subscription_date: new Date().toISOString(), 
                subscription_expires_at: expires.toISOString() 
            }).eq('id', req.user.id);
            
            res.json({ success: true, message: 'Subscription activated!', plan: PLANS[plan]?.name });
        } else {
            res.status(400).json({ success: false, message: 'Payment not successful' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Verification failed' });
    }
});

// WEBHOOK
app.post('/payment/webhook', async (req, res) => {
    try {
        if (req.body.event === 'charge.success') {
            const metadata = req.body.data.metadata;
            const userId = metadata?.user_id;
            const plan = metadata?.plan || 'standard_monthly';
            const duration = PLANS[plan]?.duration || 30;
            
            if (userId) {
                const expires = new Date(Date.now() + duration * 24 * 60 * 60 * 1000);
                await supabase.from('profiles').update({ 
                    is_subscribed: true, 
                    subscription_ref: req.body.data.reference, 
                    subscription_plan: plan,
                    subscription_date: new Date().toISOString(), 
                    subscription_expires_at: expires.toISOString() 
                }).eq('id', userId);
            }
        }
        res.sendStatus(200);
    } catch (error) {
        res.sendStatus(500);
    }
});

app.listen(PORT, () => console.log(`MZone API running on port ${PORT}`));
