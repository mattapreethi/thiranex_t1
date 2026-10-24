/**
 * @file server/server.js
 * @description Main application server bootstrap for PassGuard.
 * Features: Static file serving, compression, strict security middleware,
 * zero-knowledge enforcement, graceful shutdown, and ephemeral port support for testing.
 */

import express from 'express';
import compression from 'compression';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

import { config } from './config.js';
import { securityMiddleware } from './middleware/security.js';
import { apiLimiter } from './middleware/rateLimit.js';
import { requestLogger } from './middleware/logger.js';
import { errorHandler } from './middleware/errorHandler.js';

import healthRouter from './routes/health.js';
import wordlistRouter from './routes/wordlist.js';
import breachRangeRouter from './routes/breachRange.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export const app = express();

// Disable X-Powered-By
app.disable('x-powered-by');

// Compression middleware
app.use(compression());

// Security headers and CSP
app.use(securityMiddleware);

// Request logging (sanitized, zero-knowledge)
app.use(requestLogger);

// Rate limiting on all API routes
app.use('/api', apiLimiter);

// Zero-Knowledge Enforcement:
// Reject ANY non-GET requests to the API with 405 Method Not Allowed.
// This guarantees the server cannot and will not accept password submissions.
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({
      status: 405,
      error: 'Method Not Allowed. PassGuard operates under strict Zero-Knowledge principles and rejects data submissions.'
    });
  }
  next();
});

// Mount API routes
app.use('/api', healthRouter);
app.use('/api', wordlistRouter);
app.use('/api', breachRangeRouter);

// Unknown API routes return 404 JSON
app.all('/api/*', (req, res) => {
  res.status(404).json({
    status: 404,
    error: 'API endpoint not found.'
  });
});

// Serve static frontend files from 'public' directory
const publicDir = join(__dirname, '..', 'public');
app.use(express.static(publicDir, {
  dotfiles: 'ignore',
  etag: true,
  lastModified: true,
  maxAge: config.isProduction ? '1d' : 0
}));

// Fallback for SPA navigation: serve index.html for GET requests not matching static files
app.get('*', (req, res) => {
  res.sendFile(join(publicDir, 'index.html'));
});

// Central error handler
app.use(errorHandler);

/**
 * Start the HTTP server.
 * @param {number} [port] Port to bind to (defaults to config.port).
 * @returns {Promise<import('http').Server>}
 */
export function startServer(port = config.port) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, () => {
      const address = server.address();
      const actualPort = typeof address === 'object' && address !== null ? address.port : port;
      if (!config.isTest) {
        console.log(`[PassGuard] Server running in ${config.env} mode at http://localhost:${actualPort}`);
        console.log(`[PassGuard] Zero-Knowledge verified: no passwords are ever received by this server.`);
      }
      resolve(server);
    });

    server.on('error', (err) => {
      reject(err);
    });

    // Graceful shutdown handling
    const shutdown = (signal) => {
      if (!config.isTest) {
        console.log(`\n[PassGuard] Received ${signal}. Commencing graceful shutdown...`);
      }
      server.close(() => {
        if (!config.isTest) {
          console.log('[PassGuard] HTTP server closed gracefully. Exiting.');
        }
        process.exit(0);
      });

      // Force terminate after 5 seconds if connections linger
      setTimeout(() => {
        console.error('[PassGuard] Forcefully terminating active connections after timeout.');
        process.exit(1);
      }, 5000).unref();
    };

    process.once('SIGINT', () => shutdown('SIGINT'));
    process.once('SIGTERM', () => shutdown('SIGTERM'));
  });
}

// Auto-start if invoked directly via `node server/server.js`
const isMainModule = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMainModule) {
  startServer().catch((err) => {
    console.error('[PassGuard] Server failed to start:', err);
    process.exit(1);
  });
}

export default app;
