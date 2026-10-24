/**
 * @file server/config.js
 * @description Centralized, validated environment configuration for PassGuard.
 * Validates variables at startup and exports an immutable configuration object.
 */

function parseBoolean(val, defaultVal = true) {
  if (val === undefined || val === null || val === '') return defaultVal;
  if (typeof val === 'boolean') return val;
  const lower = String(val).trim().toLowerCase();
  if (lower === 'true' || lower === '1' || lower === 'yes') return true;
  if (lower === 'false' || lower === '0' || lower === 'no') return false;
  return defaultVal;
}

function parsePort(val, defaultPort = 3000) {
  if (val === undefined || val === null || val === '') return defaultPort;
  const parsed = parseInt(val, 10);
  if (isNaN(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid PORT configuration: "${val}". Must be an integer between 1 and 65535.`);
  }
  return parsed;
}

const env = process.env.NODE_ENV || 'development';
const port = parsePort(process.env.PORT, 3000);
const enableBreachCheck = parseBoolean(process.env.ENABLE_BREACH_CHECK, true);

export const config = Object.freeze({
  env,
  isProduction: env === 'production',
  isTest: env === 'test',
  port,
  enableBreachCheck,
  rateLimit: {
    windowMs: 60 * 1000, // 1 minute window
    max: 60              // 60 requests per minute per IP
  },
  upstreamPwnedApi: 'https://api.pwnedpasswords.com/range',
  upstreamTimeoutMs: 5000
});

export default config;
