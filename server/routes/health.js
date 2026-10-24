/**
 * @file server/routes/health.js
 * @description Health check endpoint for system monitoring and uptime inspection.
 */

import { Router } from 'express';

const router = Router();
const version = '1.0.0';

router.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    version,
    timestamp: new Date().toISOString()
  });
});

export default router;
