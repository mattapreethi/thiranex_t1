/**
 * @file server/routes/wordlist.js
 * @description Provides wordlist and keyboard pattern datasets for client-side evaluation.
 * Hardened with cryptographic ETag generation and strong HTTP caching headers.
 */

import { Router } from 'express';
import { readFileSync } from 'fs';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const router = Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Preload wordlist into memory at startup
const dataPath = join(__dirname, '..', 'data', 'common-passwords.json');
const rawData = readFileSync(dataPath, 'utf-8');
const wordlistJson = JSON.parse(rawData);

// Compute content-based ETag
const hash = createHash('sha256').update(rawData).digest('hex').substring(0, 32);
const etag = `W/"${hash}"`;

router.get('/wordlist', (req, res) => {
  // Set explicit cache headers allowing 24h browser cache
  res.setHeader('Cache-Control', 'public, max-age=86400, stale-while-revalidate=3600');
  res.setHeader('ETag', etag);

  // Conditional request revalidation
  const clientEtag = req.headers['if-none-match'];
  if (clientEtag && (clientEtag === etag || clientEtag === `"${hash}"` || clientEtag === hash)) {
    return res.status(304).end();
  }

  res.status(200).json(wordlistJson);
});

export default router;
