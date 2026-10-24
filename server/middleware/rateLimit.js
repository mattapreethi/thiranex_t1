/**
 * @file server/middleware/rateLimit.js
 * @description IP-based rate limiting for API routes using express-rate-limit.
 * Returns consistent JSON 429 responses when thresholds are exceeded.
 */

import rateLimit from 'express-rate-limit';
import { config } from '../config.js';

export const apiLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  standardHeaders: true, // Draft-6 RateLimit headers
  legacyHeaders: false,  // Disable X-RateLimit-* headers
  statusCode: 429,
  message: {
    status: 429,
    error: 'Too many requests. Please try again after 60 seconds.'
  },
  handler: (req, res, next, options) => {
    res.status(options.statusCode).json(options.message);
  }
});

export default apiLimiter;
