/**
 * @file server/middleware/security.js
 * @description Hardened HTTP security headers and CSP configuration using Helmet.
 * Enforces Zero-Knowledge principles, disables framing, and prevents inline scripts/styles.
 */

import helmet from 'helmet';

/**
 * Configured Helmet middleware with strict CSP and hardened policies.
 */
export const securityMiddleware = [
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: null // Avoid forced HTTPS redirection in local development
      }
    },
    crossOriginEmbedderPolicy: false, // Allows flexible asset loading within self
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
    xDnsPrefetchControl: { allow: false }
  }),
  // Additional security headers: Permissions-Policy disabling unused browser APIs
  (req, res, next) => {
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=(), screen-wake-lock=()'
    );
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    next();
  }
];

export default securityMiddleware;
