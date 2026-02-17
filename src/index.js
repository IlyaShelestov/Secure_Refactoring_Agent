/**
 * Main Application Entry Point
 * AI Secure Refactoring Agent Server
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import config from './config/index.js';
import logger from './utils/logger.js';
import apiRoutes from './routes/api.js';
import { closeDatabase } from './database/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: config.server.nodeEnv === 'production'
    ? process.env.ALLOWED_ORIGINS?.split(',')
    : '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: config.security.rateLimitWindowMs,
  max: config.security.rateLimitMaxRequests,
  message: {
    success: false,
    error: 'Too many requests, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Body parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
  });
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

// API routes
app.use('/api', apiRoutes);

// Serve frontend for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: config.server.nodeEnv === 'production'
      ? 'Internal server error'
      : err.message,
  });
});

// Start server
const PORT = config.server.port;
app.listen(PORT, () => {
  logger.info('🛡️  AI Secure Refactoring Agent started');
  logger.info(`📍 Server running on http://localhost:${PORT}`);
  logger.info(`🤖 Using model: ${config.gemini.model}`);
  logger.info(`🌍 Environment: ${config.server.nodeEnv}`);
});

// Graceful shutdown — close the database connection
process.on('SIGTERM', () => {
  logger.info('SIGTERM received — shutting down');
  closeDatabase();
  process.exit(0);
});
process.on('SIGINT', () => {
  logger.info('SIGINT received — shutting down');
  closeDatabase();
  process.exit(0);
});

export default app;
