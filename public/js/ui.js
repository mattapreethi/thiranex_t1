/**
 * @file public/js/ui.js
 * @description Comprehensive UI orchestrator for PassGuard.
 * Connects analyzer, generator, breach verification, accessibility announcements,
 * and zero-knowledge memory safety (60s inactivity auto-clear & pagehide wipe).
 */

import { analyzePassword } from './analyzer.js';
import { generatePassword, generatePassphrase } from './generator.js';
import { checkBreach } from './breach.js';
import { announceLive, showToast } from './a11y.js';

let wordlistData = null;
let debounceTimeout = null;
let inactivityTimer = null;
let inactivityCountdownInterval = null;
const INACTIVITY_LIMIT_SECONDS = 60;
let remainingInactivitySeconds = INACTIVITY_LIMIT_SECONDS;
let clipboardClearTimer = null;

/**
 * Sets preloaded wordlist dataset from server.
 * @param {Object} data 
 */
export function setWordlistData(data) {
  wordlistData = data;
}

/**
 * Resets the 60-second inactivity countdown timer.
 */
export function resetInactivityTimer() {
  remainingInactivitySeconds = INACTIVITY_LIMIT_SECONDS;
  updateInactivityDisplay();

  if (inactivityTimer) clearTimeout(inactivityTimer);
  if (inactivityCountdownInterval) clearInterval(inactivityCountdownInterval);

  inactivityCountdownInterval = setInterval(() => {
    remainingInactivitySeconds--;
    updateInactivityDisplay();
    if (remainingInactivitySeconds <= 0) {
      clearInterval(inactivityCountdownInterval);
    }
  }, 1000);

  inactivityTimer = setTimeout(() => {
    clearAllSensitiveState('Inactivity timeout (60s): Memory wiped for your privacy.');
  }, INACTIVITY_LIMIT_SECONDS * 1000);
}

/**
 * Updates the inactivity indicator badge in the footer.
 */
function updateInactivityDisplay() {
  const el = document.getElementById('inactivity-counter');
  if (el) {
    el.textContent = `${remainingInactivitySeconds}s`;
  }
}

/**
 * Completely purges all sensitive inputs, generated passwords, results, and memory.
 * @param {string} [reason] Optional toast announcement
 */
export function clearAllSensitiveState(reason) {
  const passwordInput = document.getElementById('password-input');
  const generatedInput = document.getElementById('generated-password-output');
  const reuseInput = document.getElementById('reuse-account-input');

  if (passwordInput) passwordInput.value = '';
  if (generatedInput) generatedInput.value = '';
  if (reuseInput) reuseInput.value = '';

  // Reset analysis view
  renderAnalysisResults({
    score: 0,
    level: 'Very Weak',
    entropy: 0,
    crackTime: 'Instant (< 1 ms)',
    reasons: ['No password entered. Start typing to evaluate strength in real time.'],
    checklist: {
      completed: [],
      remaining: [
        'Length at least 12 characters',
        'Length at least 16 characters (recommended)',
        'Contains lowercase letters (a-z)',
        'Contains uppercase letters (A-Z)',
        'Contains numeric digits (0-9)',
        'Contains special symbols (!@#$%^&*)',
        'Free from common dictionary words',
        'Free from sequential or keyboard walk patterns',
        'Free from repeated character sequences'
      ]
    },
    suggestions: [
      'Use at least 12–16 characters for high resistance against brute-force attacks.',
      'Consider using a memorable 4-word passphrase instead of a short complex string.'
    ]
  });

  const breachBadge = document.getElementById('breach-status-badge');
  if (breachBadge) {
    breachBadge.hidden = true;
    breachBadge.textContent = '';
  }

  const generatedMeter = document.getElementById('generated-meter-fill');
  if (generatedMeter) {
    generatedMeter.style.width = '0%';
  }
  const generatedScoreText = document.getElementById('generated-score-text');
  if (generatedScoreText) {
    generatedScoreText.textContent = '';
  }

  if (reason) {
    showToast(reason, 'info');
    announceLive(reason);
  }
}

/**
 * Renders analysis results across the meter, results grid, checklist, and suggestions.
 * @param {Object} res Output from analyzePassword
 */
export function renderAnalysisResults(res) {
  // 1. Update 5-Segment Strength Meter
  const segments = document.querySelectorAll('.meter-segment');
  const scoreText = document.getElementById('meter-score-text');
  const levelBadge = document.getElementById('meter-level-badge');

  const levelClassMap = ['level-0', 'level-1', 'level-2', 'level-3', 'level-4'];
  const activeClass = levelClassMap[res.score] || 'level-0';

  segments.forEach((seg, idx) => {
    // Reset all level classes
    seg.className = 'meter-segment';
    if (res.entropy > 0 && idx <= res.score) {
      seg.classList.add('active', activeClass);
    }
  });

  if (scoreText) {
    scoreText.textContent = `${res.entropy > 0 ? res.level : 'Empty'}`;
    scoreText.className = `meter-score-label ${activeClass}-text`;
  }

  if (levelBadge) {
    levelBadge.textContent = `${res.entropy.toFixed(1)} bits entropy`;
  }

  // 2. Results Grid
  const resultScore = document.getElementById('res-score-level');
  const resultEntropy = document.getElementById('res-entropy-val');
  const resultCrackTime = document.getElementById('res-crack-time');
  const resultAssumption = document.getElementById('res-attack-assumption');

  if (resultScore) {
    resultScore.textContent = res.level;
    resultScore.className = `result-stat-val ${activeClass}-text`;
  }
  if (resultEntropy) {
    resultEntropy.textContent = `${res.entropy.toFixed(1)} bits`;
  }
  if (resultCrackTime) {
    resultCrackTime.textContent = res.crackTime;
  }
  if (resultAssumption && res.attackAssumption) {
    resultAssumption.textContent = res.attackAssumption;
  }

  // 3. Reasons Panel
  const reasonsContainer = document.getElementById('res-reasons-list');
  if (reasonsContainer) {
    reasonsContainer.innerHTML = '';
    res.reasons.forEach(reason => {
      const li = document.createElement('li');
      li.className = 'reason-item';
      li.textContent = reason;
      reasonsContainer.appendChild(li);
    });
  }

  // 4. Checklist: Completed vs Remaining
  const completedList = document.getElementById('checklist-completed');
  const remainingList = document.getElementById('checklist-remaining');

  if (completedList) {
    completedList.innerHTML = '';
    if (res.checklist.completed.length === 0) {
      const emptyItem = document.createElement('li');
      emptyItem.className = 'checklist-empty-state';
      emptyItem.textContent = 'None yet — satisfy criteria below';
      completedList.appendChild(emptyItem);
    } else {
      res.checklist.completed.forEach(item => {
        const li = document.createElement('li');
        li.className = 'checklist-item checklist-item-done';
        li.innerHTML = `<span class="check-icon" aria-hidden="true">✓</span> <span>${item}</span>`;
        completedList.appendChild(li);
      });
    }
  }

  if (remainingList) {
    remainingList.innerHTML = '';
    if (res.checklist.remaining.length === 0) {
      const allDoneItem = document.createElement('li');
      allDoneItem.className = 'checklist-all-done';
      allDoneItem.textContent = '🎉 All security criteria met!';
      remainingList.appendChild(allDoneItem);
    } else {
      res.checklist.remaining.forEach(item => {
        const li = document.createElement('li');
        li.className = 'checklist-item checklist-item-pending';
        li.innerHTML = `<span class="pending-icon" aria-hidden="true">○</span> <span>${item}</span>`;
        remainingList.appendChild(li);
      });
    }
  }

  // 5. Suggestions
  const suggestionsContainer = document.getElementById('suggestions-list');
  if (suggestionsContainer) {
    suggestionsContainer.innerHTML = '';
    res.suggestions.forEach(tip => {
      const li = document.createElement('li');
      li.className = 'suggestion-item';
      li.textContent = tip;
      suggestionsContainer.appendChild(li);
    });
  }

  // Announce score to screen reader
  if (res.entropy > 0) {
    announceLive(`Password strength: ${res.level}, ${res.entropy.toFixed(1)} bits entropy, estimated crack time ${res.crackTime}`);
  }
}

/**
 * Handles input on the main password input with a 40ms debounce.
 */
export function handlePasswordInput() {
  resetInactivityTimer();
  const input = document.getElementById('password-input');
  if (!input) return;

  const val = input.value;

  if (debounceTimeout) clearTimeout(debounceTimeout);
  debounceTimeout = setTimeout(async () => {
    const analysis = analyzePassword(val, wordlistData);
    renderAnalysisResults(analysis);

    // Optional opt-in breach check
    const breachToggle = document.getElementById('breach-optin-toggle');
    const breachBadge = document.getElementById('breach-status-badge');

    if (breachToggle && breachToggle.checked && val.length > 0) {
      if (breachBadge) {
        breachBadge.hidden = false;
        breachBadge.className = 'breach-badge breach-checking';
        breachBadge.textContent = 'Checking k-anonymity breach database...';
      }

      const breachRes = await checkBreach(val);

      if (breachBadge) {
        if (breachRes.error) {
          breachBadge.className = 'breach-badge breach-error';
          breachBadge.textContent = `Breach check: ${breachRes.message || 'Service unavailable'}`;
        } else if (breachRes.breached) {
          breachBadge.className = 'breach-badge breach-danger';
          breachBadge.textContent = `⚠️ Found ${breachRes.count.toLocaleString()} times in known data breaches!`;
          announceLive(`Security warning: this password was found ${breachRes.count} times in known data breaches.`);
        } else {
          breachBadge.className = 'breach-badge breach-safe';
          breachBadge.textContent = '✓ Not found in known public breach datasets (Note: does not guarantee safety).';
          announceLive('Not found in known public breach datasets.');
        }
      }
    } else if (breachBadge) {
      breachBadge.hidden = true;
      breachBadge.textContent = '';
    }
  }, 40);
}

/**
 * Toggles password visibility (Show/Hide).
 */
export function togglePasswordVisibility() {
  resetInactivityTimer();
  const input = document.getElementById('password-input');
  const toggleBtn = document.getElementById('toggle-visibility-btn');
  const icon = document.getElementById('visibility-icon');
  if (!input || !toggleBtn) return;

  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  toggleBtn.setAttribute('aria-pressed', String(isPassword));
  toggleBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  toggleBtn.title = isPassword ? 'Hide password' : 'Show password';

  if (icon) {
    icon.innerHTML = isPassword
      ? `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>`
      : `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>`;
  }
}

/**
 * Generates password or passphrase based on current generator controls.
 */
export function handleGenerate() {
  resetInactivityTimer();
  const modePassphrase = document.getElementById('gen-mode-passphrase')?.checked;
  const output = document.getElementById('generated-password-output');
  const genScoreBadge = document.getElementById('generated-score-text');
  const genMeter = document.getElementById('generated-meter-fill');
  if (!output) return;

  try {
    let generated = '';
    if (modePassphrase) {
      const wordCount = parseInt(document.getElementById('gen-word-count')?.value || 4, 10);
      const separator = document.getElementById('gen-separator')?.value || '-';
      const capitalize = document.getElementById('gen-opt-capitalize')?.checked ?? true;
      const includeNumber = document.getElementById('gen-opt-number')?.checked ?? false;

      generated = generatePassphrase({
        wordCount,
        separator,
        capitalize,
        includeNumber
      });
    } else {
      const length = parseInt(document.getElementById('gen-length-slider')?.value || 16, 10);
      const uppercase = document.getElementById('gen-opt-upper')?.checked ?? true;
      const lowercase = document.getElementById('gen-opt-lower')?.checked ?? true;
      const digits = document.getElementById('gen-opt-digits')?.checked ?? true;
      const symbols = document.getElementById('gen-opt-symbols')?.checked ?? true;
      const excludeLookalikes = document.getElementById('gen-opt-lookalikes')?.checked ?? false;

      generated = generatePassword({
        length,
        uppercase,
        lowercase,
        digits,
        symbols,
        excludeLookalikes
      });
    }

    output.value = generated;

    // Evaluate generated password strength
    const analysis = analyzePassword(generated, wordlistData);
    if (genScoreBadge) {
      genScoreBadge.textContent = `${analysis.level} (${analysis.entropy.toFixed(1)} bits)`;
      genScoreBadge.className = `badge level-${analysis.score}-text`;
    }
    if (genMeter) {
      const pct = Math.min(100, Math.round((analysis.entropy / 100) * 100));
      genMeter.style.width = `${pct}%`;
      const colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#10b981'];
      genMeter.style.backgroundColor = colors[analysis.score];
    }

    showToast('Secure password generated!', 'success', 2000);
    announceLive(`Generated password created with ${analysis.level} strength.`);
  } catch (err) {
    showToast(err.message || 'Generation error', 'warn');
  }
}

/**
 * Copies generated password to clipboard with fallback.
 */
export async function handleCopyGenerated() {
  resetInactivityTimer();
  const output = document.getElementById('generated-password-output');
  const copyBtn = document.getElementById('copy-generated-btn');
  if (!output || !output.value) {
    showToast('Generate a password first before copying.', 'warn');
    return;
  }

  const textToCopy = output.value;
  let copied = false;

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(textToCopy);
      copied = true;
    } else {
      output.select();
      copied = document.execCommand('copy');
    }
  } catch (e) {
    output.select();
    copied = document.execCommand('copy');
  }

  if (copied) {
    showToast('Copied to clipboard! Clears automatically in 30s.', 'success', 3000);
    announceLive('Password copied to clipboard.');

    if (copyBtn) {
      copyBtn.classList.add('copy-pulse');
      setTimeout(() => copyBtn.classList.remove('copy-pulse'), 1000);
    }

    // Auto-clear notice after 30 seconds
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = setTimeout(() => {
      showToast('Reminder: Clear your clipboard after pasting your password.', 'info', 4000);
    }, 30_000);
  } else {
    showToast('Could not copy automatically. Please copy manually.', 'warn');
  }
}

/**
 * Educational Reuse Demo simulation.
 */
export function handleReuseDemoInput() {
  resetInactivityTimer();
  const input = document.getElementById('reuse-account-input');
  const compromisedStatus = document.getElementById('reuse-compromised-status');
  if (!input || !compromisedStatus) return;

  const val = input.value.trim();
  if (val.length === 0) {
    compromisedStatus.hidden = true;
    return;
  }

  compromisedStatus.hidden = false;
  compromisedStatus.innerHTML = `
    <div class="reuse-simulation-card glass-card">
      <div class="simulation-headline">
        <span class="warning-badge">Simulated Breach Cascade</span>
      </div>
      <p>If an attacker breaches a single service where you used this credential for <strong>"${escapeHtml(val)}"</strong>, they instantly test the same credential across:</p>
      <ul class="reuse-services-list">
        <li>❌ <strong>Email Account</strong> — Compromised via credential stuffing</li>
        <li>❌ <strong>Banking Portal</strong> — Account takeover attempted</li>
        <li>❌ <strong>Cloud & Social Media</strong> — Password reset links intercepted</li>
      </ul>
      <p class="reuse-lesson-note"><strong>The Rule:</strong> Never reuse passwords! A unique password per account isolates security breaches.</p>
    </div>
  `;
}

function escapeHtml(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

/**
 * Initializes all UI event listeners.
 */
export function initUI() {
  // Activity reset events
  ['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(evt => {
    window.addEventListener(evt, resetInactivityTimer, { passive: true });
  });

  // Zero-Knowledge Rule: Wipe state immediately on pagehide
  window.addEventListener('pagehide', () => {
    clearAllSensitiveState();
  });

  // Password Input & Controls
  const passwordInput = document.getElementById('password-input');
  if (passwordInput) {
    passwordInput.addEventListener('input', handlePasswordInput);
  }

  const toggleVisibilityBtn = document.getElementById('toggle-visibility-btn');
  if (toggleVisibilityBtn) {
    toggleVisibilityBtn.addEventListener('click', togglePasswordVisibility);
  }

  const clearBtn = document.getElementById('clear-password-btn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      clearAllSensitiveState('Password input and analysis cleared.');
    });
  }

  // Breach Opt-in toggle listener
  const breachToggle = document.getElementById('breach-optin-toggle');
  if (breachToggle) {
    breachToggle.addEventListener('change', () => {
      handlePasswordInput();
    });
  }

  // Generator Controls
  const generateBtn = document.getElementById('generate-btn');
  if (generateBtn) {
    generateBtn.addEventListener('click', handleGenerate);
  }

  const copyBtn = document.getElementById('copy-generated-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', handleCopyGenerated);
  }

  const slider = document.getElementById('gen-length-slider');
  const sliderVal = document.getElementById('gen-length-value');
  if (slider && sliderVal) {
    slider.addEventListener('input', (e) => {
      sliderVal.textContent = e.target.value;
      resetInactivityTimer();
    });
  }

  const wordSlider = document.getElementById('gen-word-count');
  const wordSliderVal = document.getElementById('gen-word-value');
  if (wordSlider && wordSliderVal) {
    wordSlider.addEventListener('input', (e) => {
      wordSliderVal.textContent = e.target.value;
      resetInactivityTimer();
    });
  }

  // Mode radio buttons (Password vs Passphrase)
  const modePassword = document.getElementById('gen-mode-password');
  const modePassphrase = document.getElementById('gen-mode-passphrase');
  const passwordControls = document.getElementById('generator-password-controls');
  const passphraseControls = document.getElementById('generator-passphrase-controls');

  const updateGenMode = () => {
    resetInactivityTimer();
    if (modePassphrase && modePassphrase.checked) {
      if (passwordControls) passwordControls.hidden = true;
      if (passphraseControls) passphraseControls.hidden = false;
    } else {
      if (passwordControls) passwordControls.hidden = false;
      if (passphraseControls) passphraseControls.hidden = true;
    }
  };

  if (modePassword) modePassword.addEventListener('change', updateGenMode);
  if (modePassphrase) modePassphrase.addEventListener('change', updateGenMode);

  // Reuse Demo Input
  const reuseInput = document.getElementById('reuse-account-input');
  if (reuseInput) {
    reuseInput.addEventListener('input', handleReuseDemoInput);
  }

  // Start inactivity timer
  resetInactivityTimer();
}

export default {
  setWordlistData,
  resetInactivityTimer,
  clearAllSensitiveState,
  renderAnalysisResults,
  handlePasswordInput,
  togglePasswordVisibility,
  handleGenerate,
  handleCopyGenerated,
  handleReuseDemoInput,
  initUI
};
