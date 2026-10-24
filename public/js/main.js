/**
 * @file public/js/main.js
 * @description Application entry point. Bootstraps modules, preloads cached wordlist,
 * checks backend health, and initializes interactive UI.
 */

import { initTheme } from './theme.js';
import { initAccordion } from './a11y.js';
import { initUI, setWordlistData, handleGenerate } from './ui.js';

async function bootstrap() {
  // 1. Initialize Theme first to prevent any visual flash
  initTheme();

  // 2. Initialize Accessible Accordion
  initAccordion();

  // 3. Initialize Interactive UI Event Handlers
  initUI();

  // 4. Check Backend Health
  try {
    const healthRes = await fetch('/api/health');
    if (healthRes.ok) {
      const healthData = await healthRes.json();
      const statusBadge = document.getElementById('backend-status-badge');
      if (statusBadge) {
        statusBadge.className = 'status-badge status-online';
        statusBadge.innerHTML = `<span class="status-dot"></span> Online (v${healthData.version})`;
      }
    }
  } catch (err) {
    const statusBadge = document.getElementById('backend-status-badge');
    if (statusBadge) {
      statusBadge.className = 'status-badge status-offline';
      statusBadge.innerHTML = `<span class="status-dot"></span> Offline / Standalone`;
    }
  }

  // 5. Preload Wordlist and Keyboard Patterns from Backend
  // Browser will automatically use ETag / 304 Not Modified
  try {
    const wordlistRes = await fetch('/api/wordlist');
    if (wordlistRes.ok) {
      const wordlistJson = await wordlistRes.json();
      setWordlistData(wordlistJson);
    }
  } catch (err) {
    // If offline or network error, analyzer gracefully uses built-in core lists
  }

  // 6. Pre-populate generator with an initial safe demonstration password
  handleGenerate();
}

// Bootstrap once DOM content is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootstrap);
} else {
  bootstrap();
}
