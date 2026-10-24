/**
 * @file server/middleware/logger.js
 * @description Privacy-preserving request logging middleware.
 * Zero-Knowledge rule: ONLY logs HTTP method, sanitized path, status code, and duration.
 * Explicitly strips and NEVER logs query strings, headers, request bodies, or payloads.
 */

export function requestLogger(req, res, next) {
  // Ignore logging during automated test runs to keep test output pristine
  if (process.env.NODE_ENV === 'test') {
    return next();
  }

  const startTime = process.hrtime.bigint();

  // Strip query parameters to prevent accidental token/credential logging
  const safePath = req.path || '/';

  res.on('finish', () => {
    const endTime = process.hrtime.bigint();
    const durationMs = Number(endTime - startTime) / 1e6;
    const status = res.statusCode;
    const method = req.method;

    const logLine = `[${new Date().toISOString()}] ${method} ${safePath} ${status} - ${durationMs.toFixed(2)}ms`;
    if (status >= 400) {
      console.warn(logLine);
    } else {
      console.log(logLine);
    }
  });

  next();
}

export default requestLogger;
