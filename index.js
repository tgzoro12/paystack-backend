const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Your Paystack SECRET key (set in Render environment variables)
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// Middleware
app.use(cors());
app.use(express.json());

// Health check
app.get('/', (req, res) => {
    res.json({ 
        status: 'online', 
        message: 'Paystack Verification Server Running',
        timestamp: new Date().toISOString()
    });
});

// Verify payment endpoint
app.get('/verify/:reference', async (req, res) => {
    const { reference } = req.params;

    if (!reference) {
        return res.status(400).json({ 
            success: false, 
            message: 'Payment reference is required' 
        });
    }

    if (!PAYSTACK_SECRET_KEY) {
        return res.status(500).json({ 
            success: false, 
            message: 'Server configuration error' 
        });
    }

    try {
        const response = await axios.get(
            `https://api.paystack.co/transaction/verify/${reference}`,
            {
                headers: {
                    'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const data = response.data;

        if (data.status && data.data.status === 'success') {
            // Payment verified successfully
            return res.json({
                success: true,
                message: 'Payment verified successfully',
                data: {
                    reference: data.data.reference,
                    amount: data.data.amount / 100, // Convert from kobo to naira
                    currency: data.data.currency,
                    email: data.data.customer.email,
                    paid_at: data.data.paid_at,
                    channel: data.data.channel
                }
            });
        } else {
            // Payment not successful
            return res.status(400).json({
                success: false,
                message: 'Payment not successful',
                status: data.data?.status || 'unknown'
            });
        }

    } catch (error) {
        console.error('Verification error:', error.response?.data || error.message);
        
        return res.status(500).json({
            success: false,
            message: 'Error verifying payment',
            error: error.response?.data?.message || error.message
        });
    }
});

// Webhook endpoint (for Paystack notifications)
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
    const hash = require('crypto')
        .createHmac('sha512', PAYSTACK_SECRET_KEY)
        .update(JSON.stringify(req.body))
        .digest('hex');

    if (hash === req.headers['x-paystack-signature']) {
        const event = req.body;
        console.log('Webhook received:', event.event);

        // Handle different events
        if (event.event === 'charge.success') {
            console.log('Payment successful:', event.data.reference);
            // You can add database storage here
        }
    }

    res.sendStatus(200);
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📍 Health check: http://localhost:${PORT}/`);
    console.log(`🔐 Verify endpoint: http://localhost:${PORT}/verify/:reference`);
});
