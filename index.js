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

const PLANS = {
    standard_monthly: { name: 'Standard Monthly', amount: 1600000, duration: 30 },
    standard_yearly: { name: 'Standard Yearly', amount: 14500000, duration: 365 },
    pro_monthly: { name: 'Pro Monthly', amount: 2200000, duration: 30 },
    pro_yearly: { name: 'Pro Yearly', amount: 22000000, duration: 365 }
};

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

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
    res.json({ status: 'online', message: 'MZone API Running' });
});

app.get('/plans', (req, res) => {
    const planList = Object.entries(PLANS).map(([key, value]) => ({
        id: key, name: value.name, amount: value.amount / 100, duration: value.duration
    }));
    res.json({ success: true, plans: planList });
});

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
        
        const { data: newUser, error } = await supabase.from('profiles').insert({
            email: email.toLowerCase(),
            password_hash: hashedPassword,
            full_name: fullName,
            email_verified: true,
            is_subscribed: false
        }).select().single();
        
        if (error) {
            console.error('DB Error:', error);
            return res.status(500).json({ success: false, message: 'Failed to create account' });
        }
        
        try {
            await resend.emails.send({
                from: 'MZone <onboarding@resend.dev>',
                to: email,
                subject: 'Welcome to MZone!',
                html: `<div style="font-family:Arial;max-width:500px;margin:0 auto;padding:20px;background:#0a0a0f;color:#fff;border-radius:10px;"><h1 style="color:#8b5cf6;text-align:center;">🎬 MZone</h1><p>Hello ${fullName},</p><p>Welcome to MZone! Your account has been created successfully.</p></div>`
            });
        } catch (e) { console.error('Email error:', e); }
        
        const token = jwt.sign({ id: newUser.id, email: newUser.email, fullName: newUser.full_name }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ 
            success: true, 
            message: 'Account created!', 
            token,
            user: { id: newUser.id, email: newUser.email, fullName: newUser.full_name, isSubscribed: false }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
        const { data: user } = await supabase.from('profiles').select('*').eq('email', email.toLowerCase()).single();
        if (!user) return res.status(400).json({ success: false, message: 'Invalid credentials' });
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(400).json({ success: false, message: 'Invalid credentials' });
        
        const token = jwt.sign({ id: user.id, email: user.email, fullName: user.full_name }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ 
            success: true, 
            token, 
            user: { id: user.id, email: user.email, fullName: user.full_name, isSubscribed: user.is_subscribed, subscriptionPlan: user.subscription_plan, subscriptionExpires: user.subscription_expires_at }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/auth/me', verifyToken, async (req, res) => {
    try {
        const { data: user } = await supabase.from('profiles').select('*').eq('id', req.user.id).single();
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        let isSubscribed = user.is_subscribed;
        if (user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date()) {
            isSubscribed = false;
            await supabase.from('profiles').update({ is_subscribed: false }).eq('id', user.id);
        }
        res.json({ success: true, user: { id: user.id, email: user.email, fullName: user.full_name, isSubscribed, subscriptionPlan: user.subscription_plan, subscriptionExpires: user.subscription_expires_at } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/payment/initialize', verifyToken, async (req, res) => {
    try {
        const { plan } = req.body;
        if (!plan || !PLANS[plan]) {
            return res.status(400).json({ success: false, message: 'Invalid plan' });
        }
        const selectedPlan = PLANS[plan];
        const { data: user } = await supabase.from('profiles').select('*').eq('id', req.user.id).single();
        if (!user) return res.status(400).json({ success: false, message: 'User not found' });
        
        const response = await axios.post('https://api.paystack.co/transaction/initialize', {
            email: user.email,
            amount: selectedPlan.amount,
            callback_url: `${FRONTEND_URL}/dashboard.html?payment=success`,
            metadata: { user_id: user.id, plan: plan, duration: selectedPlan.duration }
        }, { headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' } });
        
        res.json({ success: true, authorization_url: response.data.data.authorization_url, reference: response.data.data.reference });
    } catch (error) {
        console.error('Payment init error:', error.response?.data || error);
        res.status(500).json({ success: false, message: 'Payment init failed' });
    }
});

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
            
            res.json({ success: true, message: 'Subscription activated!' });
        } else {
            res.status(400).json({ success: false, message: 'Payment not successful' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Verification failed' });
    }
});

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
