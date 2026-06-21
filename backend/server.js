require('dotenv').config();
const express = require('express');
const cors = require('cors');
const authMiddleware = require('./middleware/auth');
const auctionsRouter = require('./routes/auctions');
const itemsRouter = require('./routes/items');
const biddersRouter = require('./routes/bidders');
const winnersRouter = require('./routes/winners');
const paymentsRouter = require('./routes/payments');
const settingsRouter = require('./routes/settings');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API Key authentication (all routes)
app.use(authMiddleware);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Routes
app.use('/api/auctions', auctionsRouter);
app.use('/api/items', itemsRouter);
app.use('/api/bidders', biddersRouter);
app.use('/api/winners', winnersRouter);
app.use('/api/payments', paymentsRouter);
app.use('/api/settings', settingsRouter);

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`SAM Backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`CORS origin: ${process.env.CORS_ORIGIN || 'any'}`);
});

module.exports = app;
