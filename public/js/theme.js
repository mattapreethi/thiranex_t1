/**
 * @file public/js/theme.js
 * @description Theme management (Dark Navy Glass / Light Lavender Neumorphic).
 * Strictly conforms to Zero-Knowledge rules: only stores 'passguard-theme' in localStorage.
 * Respects OS 'prefers-color-scheme' by default.
 */

const STORAGE_KEY = 'passguard-theme';

/**
 * Detects initial theme based on stored preference or system preference.
 * @returns {'dark' | 'light'}
 */
export function getInitialTheme() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved === 'dark' || saved === 'light') {
    return saved;
  }
  // System media query fallback
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    return 'light';
  }
  return 'dark';
}

/**
 * Applies theme attribute to document root and updates toggle button.
 * @param {'dark' | 'light'} theme 
 */
export function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const toggleBtn = document.getElementById('theme-toggle-btn');
  if (toggleBtn) {
    const isLight = theme === 'light';
    toggleBtn.setAttribute('aria-pressed', String(isLight));
    toggleBtn.setAttribute(
      'aria-label',
      isLight ? 'Switch to Dark Theme' : 'Switch to Light Theme'
    );
    toggleBtn.title = isLight ? 'Switch to Dark Theme' : 'Switch to Light Theme';
  }
}

/**
 * Toggles between dark and light themes and persists choice.
 * @returns {'dark' | 'light'} The newly applied theme.
 */
export function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  localStorage.setItem(STORAGE_KEY, next);
  applyTheme(next);
  return next;
}

/**
 * Initializes theme listeners and handles OS preference changes.
 */
export function initTheme() {
  const initial = getInitialTheme();
  applyTheme(initial);

  const toggleBtn = document.getElementById('theme-toggle-btn');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      toggleTheme();
    });
  }

  // Listen for OS scheme changes if no manual preference is stored
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
      if (!localStorage.getItem(STORAGE_KEY)) {
        applyTheme(e.matches ? 'light' : 'dark');
      }
    });
  }
}

export default {
  getInitialTheme,
  applyTheme,
  toggleTheme,
  initTheme
};
