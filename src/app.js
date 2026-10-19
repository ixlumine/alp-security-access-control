const express = require('express');
const cors = require('cors');
const path = require('path');
const passport = require('./config/passport');

const authRouter = require('./routes/auth');
const adminRouter = require('./routes/admin');
const productsRouter = require('./routes/products');
const ordersRouter = require('./routes/orders');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// Static dashboard files
app.use(express.static(path.join(__dirname, '../public')));

// Health check endpoint
app.get('/api/health', (req, res) => {
  return res.json({
    status: 'ok',
    name: 'E-Commerce Security & Authorization API'
  });
});

// Route mount points
app.use('/api/auth', authRouter);
app.use('/auth', authRouter); // For Google OAuth redirects
app.use('/api/admin', adminRouter);
app.use('/api/products', productsRouter);
app.use('/api/orders', ordersRouter);

// Database reseed endpoint for interactive testing / demo
const { seedDatabase } = require('./db/seed');
app.post('/api/seed', (req, res) => {
  try {
    const result = seedDatabase();
    return res.json({ message: 'Database reset to initial seed state', ...result });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to reseed database', details: err.message });
  }
});

// Fallback 404 handler for API routes
app.use('/api', (req, res) => {
  return res.status(404).json({ error: 'Endpoint not found' });
});

// Fallback error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Application Error:', err);
  return res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error'
  });
});

module.exports = app;
