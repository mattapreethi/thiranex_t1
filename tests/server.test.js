/**
 * @file tests/server.test.js
 * @description Automated backend integration tests for PassGuard server using node:test.
 * Tests health check, wordlist ETag revalidation, k-anonymity validation,
 * rate limiting, security headers, and Zero-Knowledge POST rejection (404/405).
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer } from '../server/server.js';

describe('PassGuard Server API & Security Hardening', () => {
  let serverInstance = null;
  let baseUrl = '';

  before(async () => {
    // Set test environment
    process.env.NODE_ENV = 'test';
    // Ephemeral port binding (port 0)
    serverInstance = await startServer(0);
    const address = serverInstance.address();
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  after(() => {
    if (serverInstance) {
      serverInstance.close();
    }
  });

  test('GET /api/health returns 200 with ok status, uptime, and version', async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.equal(json.status, 'ok');
    assert.equal(typeof json.uptime, 'number');
    assert.equal(json.version, '1.0.0');
  });

  test('GET /api/wordlist returns valid JSON with ETag and Cache-Control', async () => {
    const res = await fetch(`${baseUrl}/api/wordlist`);
    assert.equal(res.status, 200);

    const etag = res.headers.get('etag');
    const cacheControl = res.headers.get('cache-control');

    assert.ok(etag, 'ETag header must be present');
    assert.ok(cacheControl && cacheControl.includes('public'), 'Cache-Control header must be set');

    const json = await res.json();
    assert.ok(Array.isArray(json.commonPasswords), 'commonPasswords must be an array');
    assert.ok(json.commonPasswords.length >= 500, `Expected at least 500 common passwords, got ${json.commonPasswords.length}`);
    assert.ok(Array.isArray(json.keyboardPatterns), 'keyboardPatterns must be an array');

    // Test conditional revalidation with If-None-Match (HTTP 304)
    const revalRes = await fetch(`${baseUrl}/api/wordlist`, {
      headers: {
        'If-None-Match': etag
      }
    });
    assert.equal(revalRes.status, 304, 'Server must return 304 Not Modified when ETag matches');
  });

  test('GET /api/breach-range/:prefix rejects invalid prefixes with 400', async () => {
    const invalidPrefixes = ['123', 'too-long', '1234g', 'ZZZZZ', '123456', 'xyz12', '???', '!@#$%'];

    for (const prefix of invalidPrefixes) {
      const res = await fetch(`${baseUrl}/api/breach-range/${encodeURIComponent(prefix)}`);
      assert.equal(res.status, 400, `Prefix "${prefix}" should be rejected with 400`);
      const json = await res.json();
      assert.ok(json.error && json.error.includes('hexadecimal'));
    }
  });

  test('Security headers: Helmet CSP, Referrer-Policy, nosniff, and Permissions-Policy present', async () => {
    const res = await fetch(`${baseUrl}/api/health`);

    const csp = res.headers.get('content-security-policy');
    const referrer = res.headers.get('referrer-policy');
    const nosniff = res.headers.get('x-content-type-options');
    const permissions = res.headers.get('permissions-policy');
    const frameOptions = res.headers.get('x-frame-options');

    assert.ok(csp, 'Content-Security-Policy must be present');
    assert.ok(csp.includes("default-src 'self'"), "CSP must include default-src 'self'");
    assert.ok(csp.includes("frame-ancestors 'none'"), "CSP must disallow framing");
    assert.equal(referrer, 'no-referrer', 'Referrer-Policy must be no-referrer');
    assert.equal(nosniff, 'nosniff', 'X-Content-Type-Options must be nosniff');
    assert.ok(permissions && permissions.includes('camera=()'), 'Permissions-Policy must disable unused features');
    assert.equal(frameOptions, 'DENY', 'X-Frame-Options must be DENY');
  });

  test('Zero-Knowledge Rule: No route accepts or echoes a password (POST returns 404 or 405)', async () => {
    const forbiddenEndpoints = [
      '/api/password',
      '/api/analyze',
      '/api/check',
      '/api/breach-check',
      '/api/health',
      '/api/wordlist'
    ];

    for (const endpoint of forbiddenEndpoints) {
      const res = await fetch(`${baseUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password: 'SuperSecretPassword123!' })
      });

      // Must be either 405 Method Not Allowed or 404 Not Found
      assert.ok(
        [404, 405].includes(res.status),
        `POST ${endpoint} returned ${res.status}. All POST requests to API must be strictly rejected with 404/405!`
      );
    }
  });

  test('Rate limiting on /api/* returns 429 when threshold exceeded', async () => {
    // Send rapid requests to exceed the 60 req/min rate limit
    let hitRateLimit = false;

    for (let i = 0; i < 75; i++) {
      const res = await fetch(`${baseUrl}/api/health`);
      if (res.status === 429) {
        hitRateLimit = true;
        const json = await res.json();
        assert.equal(json.status, 429);
        break;
      }
    }

    assert.ok(hitRateLimit, 'Rate limiter did not trigger 429 after 60+ rapid requests');
  });

});
