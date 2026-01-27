const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

/* ================= ENV ================= */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const resend = new Resend(process.env.RESEND_API_KEY);
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'mzone_secret_2025';
const FRONTEND_URL = 'https://tgzoro12.github.io/mzone';

/* ================= PLANS ================= */
const PLANS = {
  standard_monthly: { name: 'Standard Monthly', amount: 1600000, duration: 30 },
  standard_yearly: { name: 'Standard Yearly', amount: 14500000, duration: 365 },
  pro_monthly: { name: 'Pro Monthly', amount: 2200000, duration: 30 },
  pro_yearly: { name: 'Pro Yearly', amount: 22000000, duration: 365 }
};

/* ================= DISCOUNT CODES ================= */
const DISCOUNT_CODES = {
  MZONE50: { percent: 56, active: true },
  VIP2025: { percent: 56, active: true },
  LAUNCH2025: { percent: 56, active: true }
};

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: '*'}));
app.use(express.json());

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false });
  }
}

/* ================= BASIC ================= */
app.get('/', (req, res) => {
  res.json({ status: 'online', service: 'MZone API' });
});

app.get('/plans', (req, res) => {
  const list = Object.entries(PLANS).map(([id, p]) => ({
    id,
    name: p.name,
    amount: p.amount / 100,
    duration: p.duration
  }));
  res.json({ success: true, plans: list });
});

/* ================= AUTH ================= */
app.post('/auth/register', async (req, res) => {
  const { email, password, fullName } = req.body;
  if (!email || !password || !fullName)
    return res.status(400).json({ success: false });

  const hash = await bcrypt.hash(password, 12);

  const { error } = await supabase.from('profiles').insert({
    email: email.toLowerCase(),
    password_hash: hash,
    full_name: fullName,
    is_subscribed: false
  });

  if (error) return res.status(500).json({ success: false });

  try {
    await resend.emails.send({
      from: 'MZone <onboarding@resend.dev>',
      to: email,
      subject: 'Welcome to MZone',
      html: `<h2>Welcome ${fullName}</h2>`
    });
  } catch {}

  res.json({ success: true });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  const { data: user } = await supabase
    .from('profiles')
    .select('*')
    .eq('email', email.toLowerCase())
    .single();

  if (!user) return res.status(400).json({ success: false });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ success: false });

  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    success: true,
    token,
    user
  });
});

/* ================= PAYMENT INIT ================= */
app.post('/payment/initialize', auth, async (req, res) => {
  const { plan, discountCode } = req.body;
  if (!PLANS[plan]) return res.status(400).json({ success: false });

  let amount = PLANS[plan].amount;
  let appliedDiscount = null;

  if (discountCode) {
    const code = discountCode.toUpperCase();
    if (DISCOUNT_CODES[code]?.active) {
      amount = Math.floor(
        amount * (100 - DISCOUNT_CODES[code].percent) / 100
      );
      appliedDiscount = code;
    }
  }

  const { data: user } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', req.user.id)
    .single();

  const response = await axios.post(
    'https://api.paystack.co/transaction/initialize',
    {
      email: user.email,
      amount,
      callback_url: `${FRONTEND_URL}/dashboard.html`,
      metadata: {
        user_id: user.id,
        plan,
        duration: PLANS[plan].duration,
        discount_code: appliedDiscount
      }
    },
    {
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`
      }
    }
  );

  res.json({
    success: true,
    url: response.data.data.authorization_url
  });
});

/* ================= VERIFY ================= */
app.get('/payment/verify/:ref', auth, async (req, res) => {
  const r = await axios.get(
    `https://api.paystack.co/transaction/verify/${req.params.ref}`,
    { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
  );

  if (r.data.data.status !== 'success')
    return res.status(400).json({ success: false });

  const meta = r.data.data.metadata;
  const expires = new Date(
    Date.now() + meta.duration * 86400000
  );

  await supabase.from('profiles').update({
    is_subscribed: true,
    subscription_plan: meta.plan,
    subscription_expires_at: expires.toISOString(),
    discount_code_used: meta.discount_code
  }).eq('id', meta.user_id);

  res.json({ success: true });
});

/* ================= START ================= */
app.listen(PORT, () =>
  console.log('MZone backend running on', PORT)
);
