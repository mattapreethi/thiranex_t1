/**
 * @file public/js/breach.js
 * @description Zero-Knowledge k-Anonymity Breach Verification.
 * Computes SHA-1 hash locally using the browser's native Web Crypto API (crypto.subtle).
 * Transmits ONLY the first 5 hexadecimal characters to the backend proxy.
 * Matches the remaining 35 suffix characters LOCALLY in the client memory.
 * Neither the backend nor HaveIBeenPwned ever sees the password or full hash.
 */

/**
 * Computes hexadecimal SHA-1 hash of a string using Web Crypto API.
 * @param {string} str 
 * @returns {Promise<string>} 40-character uppercase hexadecimal string
 */
export async function computeSha1Hex(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Parses HIBP range format response: "SUFFIX:COUNT\r\nSUFFIX:COUNT..."
 * @param {string} rawData 
 * @returns {Map<string, number>} Map of 35-character suffix -> breach count
 */
export function parseRangeResponse(rawData) {
  const map = new Map();
  if (!rawData || typeof rawData !== 'string') return map;

  const lines = rawData.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [suffix, countStr] = trimmed.split(':');
    if (suffix && countStr) {
      map.set(suffix.toUpperCase(), parseInt(countStr, 10) || 0);
    }
  }
  return map;
}

/**
 * Performs client-side k-anonymity breach check against the proxy endpoint.
 * @param {string} password 
 * @returns {Promise<{ breached: boolean, count: number, error?: boolean, message?: string }>}
 */
export async function checkBreach(password) {
  if (!password) {
    return { breached: false, count: 0 };
  }

  try {
    const fullHash = await computeSha1Hex(password);
    const prefix = fullHash.substring(0, 5);
    const suffix = fullHash.substring(5);

    const response = await fetch(`/api/breach-range/${prefix}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });

    if (response.status === 503) {
      return {
        breached: false,
        count: 0,
        error: true,
        message: 'Breach check service is disabled on the server.'
      };
    }

    if (!response.ok) {
      return {
        breached: false,
        count: 0,
        error: true,
        message: 'Breach verification server is currently unreachable.'
      };
    }

    const json = await response.json();
    const suffixData = json.data || '';
    const suffixMap = parseRangeResponse(suffixData);

    if (suffixMap.has(suffix)) {
      const count = suffixMap.get(suffix) || 1;
      return { breached: true, count };
    }

    return { breached: false, count: 0 };
  } catch (err) {
    return {
      breached: false,
      count: 0,
      error: true,
      message: 'Network error during breach verification. Offline mode active.'
    };
  }
}

export default {
  computeSha1Hex,
  parseRangeResponse,
  checkBreach
};
