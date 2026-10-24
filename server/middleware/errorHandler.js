/**
 * @file server/middleware/errorHandler.js
 * @description Centralized error handler returning safe JSON responses without stack traces.
 */

import { config } from '../config.js';

export function errorHandler(err, req, res, next) {
  // If response headers have already been sent, delegate to standard Express handler
  if (res.headersSent) {
    return next(err);
  }

  const statusCode = err.status || err.statusCode || 500;
  
  // In production or test, provide sanitized generic message to avoid information disclosure
  const safeMessage = config.isProduction
    ? 'An unexpected error occurred. Please try again later.'
    : (err.message || 'Internal Server Error');

  res.status(statusCode).json({
    status: statusCode,
    error: safeMessage
  });
}

export default errorHandler;
