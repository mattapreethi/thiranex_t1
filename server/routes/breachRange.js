/**
 * @file server/routes/breachRange.js
 * @description Zero-knowledge k-anonymity breach range proxy.
 * Only accepts a 5-character SHA-1 hexadecimal prefix.
 * Proxies request to haveibeenpwned range API with Add-Padding: true.
 * Upstream failure returns HTTP 502 Bad Gateway; invalid prefix returns HTTP 400.
 */

import { Router } from 'express';
import { config } from '../config.js';

const router = Router();
const PREFIX_REGEX = /^[A-Fa-f0-9]{5}$/;

router.get(['/breach-range', '/breach-range/:prefix'], async (req, res) => {
  // Check if breach checking is enabled on this server
  if (!config.enableBreachCheck) {
    return res.status(503).json({
      status: 503,
      error: 'Breach range verification is disabled on this server instance.'
    });
  }

  const prefix = req.params.prefix || '';

  // Strict 5-character hex validation
  if (!prefix || !PREFIX_REGEX.test(prefix)) {
    return res.status(400).json({
      status: 400,
      error: 'Invalid prefix format. Prefix must consist of exactly 5 hexadecimal characters.'
    });
  }

  const normalizedPrefix = prefix.toUpperCase();
  const upstreamUrl = `${config.upstreamPwnedApi}/${normalizedPrefix}`;

  try {
    const upstreamResponse = await fetch(upstreamUrl, {
      method: 'GET',
      headers: {
        'Add-Padding': 'true',
        'User-Agent': 'PassGuard-ZeroKnowledge-Analyzer/1.0'
      },
      signal: AbortSignal.timeout(config.upstreamTimeoutMs)
    });

    if (!upstreamResponse.ok) {
      return res.status(502).json({
        status: 502,
        error: `Upstream breach service returned status ${upstreamResponse.status}.`
      });
    }

    const textData = await upstreamResponse.text();

    // Cache the range response for 1 hour to reduce upstream queries
    res.setHeader('Cache-Control', 'public, max-age=3600');
    return res.status(200).json({
      prefix: normalizedPrefix,
      data: textData
    });
  } catch (error) {
    return res.status(502).json({
      status: 502,
      error: 'Upstream breach verification service is unreachable or timed out.'
    });
  }
});

export default router;
