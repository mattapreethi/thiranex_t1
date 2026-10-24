/**
 * @file public/js/a11y.js
 * @description Accessibility helpers, keyboard navigation, throttled screen-reader announcements,
 * and interactive accessible accordion management.
 */

let announceTimeout = null;

/**
 * Announces a message to assistive technologies via a dedicated polite live region.
 * Throttled to prevent flooding screen readers while the user is rapidly typing.
 * @param {string} message 
 * @param {number} [delay=350] Throttle duration in ms
 */
export function announceLive(message, delay = 350) {
  const liveRegion = document.getElementById('a11y-live-region');
  if (!liveRegion) return;

  if (announceTimeout) {
    clearTimeout(announceTimeout);
  }

  announceTimeout = setTimeout(() => {
    liveRegion.textContent = '';
    // Small timeout before setting content ensures screen readers notice the mutation
    setTimeout(() => {
      liveRegion.textContent = message;
    }, 50);
  }, delay);
}

/**
 * Initializes accessible accordion behavior.
 * Supports click, Enter, Space, and Arrow Up/Down navigation between accordion headers.
 */
export function initAccordion() {
  const accordionButtons = document.querySelectorAll('.accordion-header');

  accordionButtons.forEach((btn, index) => {
    btn.addEventListener('click', () => {
      const isExpanded = btn.getAttribute('aria-expanded') === 'true';
      const panelId = btn.getAttribute('aria-controls');
      const panel = document.getElementById(panelId);

      // Toggle state
      btn.setAttribute('aria-expanded', String(!isExpanded));
      if (panel) {
        if (isExpanded) {
          panel.hidden = true;
          panel.classList.remove('is-open');
        } else {
          panel.hidden = false;
          panel.classList.add('is-open');
        }
      }
    });

    btn.addEventListener('keydown', (e) => {
      let targetIndex = null;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        targetIndex = (index + 1) % accordionButtons.length;
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        targetIndex = (index - 1 + accordionButtons.length) % accordionButtons.length;
      } else if (e.key === 'Home') {
        e.preventDefault();
        targetIndex = 0;
      } else if (e.key === 'End') {
        e.preventDefault();
        targetIndex = accordionButtons.length - 1;
      }

      if (targetIndex !== null) {
        accordionButtons[targetIndex].focus();
      }
    });
  });
}

/**
 * Shows an ephemeral toast notification that is both visually polished and accessible.
 * @param {string} message 
 * @param {'info' | 'success' | 'warn'} [type='info']
 * @param {number} [duration=3000]
 */
export function showToast(message, type = 'info', duration = 3000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type} glass-card`;
  toast.setAttribute('role', 'status');
  toast.textContent = message;

  container.appendChild(toast);
  announceLive(message, 50);

  // Trigger entrance transition
  requestAnimationFrame(() => {
    toast.classList.add('toast-visible');
  });

  setTimeout(() => {
    toast.classList.remove('toast-visible');
    toast.addEventListener('transitionend', () => {
      toast.remove();
    }, { once: true });
  }, duration);
}

export default {
  announceLive,
  initAccordion,
  showToast
};
