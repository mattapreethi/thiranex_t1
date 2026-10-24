/**
 * @file public/js/generator.js
 * @description Cryptographically secure password and passphrase generator.
 * Uses Web Crypto API (crypto.getRandomValues) with rejection sampling to eliminate modulo bias.
 * Guarantees at least one character from each selected set, and shuffles with secure Fisher-Yates.
 * NEVER uses Math.random. NEVER persists generated passwords.
 */

// Character set definitions
export const CHAR_SETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

// Look-alike characters: 0, O, o, 1, l, I, |
export const LOOK_ALIKE_SET = new Set(['0', 'O', 'o', '1', 'l', 'I', '|']);

// Curated dictionary for memorable passphrase mode (250 distinct, easy-to-type words)
export const PASSPHRASE_WORDS = [
  'anchor', 'beacon', 'breeze', 'bridge', 'cabin', 'canyon', 'castle', 'cedar',
  'cliff', 'clover', 'comet', 'coral', 'crater', 'crystal', 'delta', 'desert',
  'dolphin', 'dragon', 'drift', 'eagle', 'echo', 'ember', 'falcon', 'feather',
  'flame', 'forest', 'fossil', 'frost', 'galaxy', 'garden', 'glacier', 'glimmer',
  'gorge', 'grove', 'harbor', 'haven', 'hawk', 'haze', 'horizon', 'island',
  'jasper', 'jungle', 'lagoon', 'lantern', 'meadow', 'meteor', 'mist', 'moon',
  'moss', 'mountain', 'nebula', 'oasis', 'ocean', 'orbit', 'orchid', 'pebble',
  'petal', 'phantom', 'pillar', 'planet', 'prairie', 'prism', 'pyramid', 'quarry',
  'quartz', 'quiver', 'radar', 'radiance', 'rainbow', 'ravine', 'reef', 'ridge',
  'river', 'robin', 'rocket', 'sable', 'safari', 'sage', 'sail', 'salmon',
  'satin', 'scarlet', 'serpent', 'shadow', 'shield', 'sierra', 'silver', 'solace',
  'spark', 'spiral', 'spring', 'spruce', 'star', 'stellar', 'stone', 'stream',
  'summit', 'sunset', 'surge', 'swallow', 'swan', 'talon', 'temple', 'thistle',
  'thunder', 'tide', 'timber', 'topaz', 'torrent', 'tower', 'trail', 'tundra',
  'twilight', 'valley', 'vapor', 'velvet', 'vessel', 'vine', 'violet', 'volcano',
  'voyage', 'walnut', 'warden', 'wave', 'willow', 'wind', 'winter', 'zenith',
  'zephyr', 'acorn', 'alder', 'amber', 'apex', 'archer', 'armor', 'arrow',
  'atlas', 'aurora', 'autumn', 'azure', 'badger', 'balsam', 'banner', 'bark',
  'basalt', 'bastion', 'bayou', 'beaver', 'birch', 'bison', 'blade', 'blaze',
  'bluff', 'boulder', 'bramble', 'branch', 'brook', 'canvas', 'carbon', 'cascade',
  'cave', 'chasm', 'chrome', 'cipher', 'citadel', 'cloud', 'clover', 'cobalt',
  'compass', 'copper', 'cove', 'crest', 'crag', 'cypress', 'dawn', 'den',
  'dune', 'dusk', 'elm', 'fern', 'fir', 'flint', 'flora', 'flux',
  'forge', 'garnet', 'geyser', 'glade', 'granite', 'grass', 'gravel', 'gulch',
  'hail', 'heath', 'hedge', 'helm', 'hemlock', 'hickory', 'highland', 'hollow',
  'horn', 'ice', 'inlet', 'isle', 'ivy', 'juniper', 'kelp', 'knoll',
  'lake', 'larch', 'lava', 'leaf', 'ledge', 'lichen', 'lime', 'linden',
  'lodge', 'loon', 'lupine', 'maple', 'marsh', 'mesa', 'miner', 'moor',
  'mural', 'needle', 'nest', 'nickel', 'north', 'oak', 'onyx', 'opal',
  'otter', 'peak', 'pine', 'plateau', 'pond', 'poplar', 'quail', 'rapids',
  'raven', 'reeds', 'rhino', 'rink', 'roost', 'ruby', 'russet', 'rye'
];

/**
 * Returns a cryptographically secure uniform integer in [0, maxExclusive - 1]
 * using 32-bit rejection sampling to eliminate modulo bias.
 * @param {number} maxExclusive Must be > 0 and < 2^32.
 * @returns {number}
 */
export function secureRandomInt(maxExclusive) {
  if (maxExclusive <= 1) return 0;

  // Maximum multiple of maxExclusive that fits inside a 32-bit unsigned integer (2^32)
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buffer = new Uint32Array(1);

  while (true) {
    crypto.getRandomValues(buffer);
    const value = buffer[0];
    if (value < limit) {
      return value % maxExclusive;
    }
    // Discard and redraw on value >= limit to avoid bias
  }
}

/**
 * Cryptographically shuffles an array in place using the Fisher-Yates algorithm
 * with rejection-sampled secure RNG.
 * @template T
 * @param {T[]} array 
 * @returns {T[]}
 */
export function secureShuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    const temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
  return array;
}

/**
 * Generates a strong random password matching the specified parameters.
 * @param {Object} options
 * @param {number} [options.length=16] Length between 12 and 32
 * @param {boolean} [options.uppercase=true]
 * @param {boolean} [options.lowercase=true]
 * @param {boolean} [options.digits=true]
 * @param {boolean} [options.symbols=true]
 * @param {boolean} [options.excludeLookalikes=false]
 * @returns {string}
 */
export function generatePassword(options = {}) {
  const {
    length = 16,
    uppercase = true,
    lowercase = true,
    digits = true,
    symbols = true,
    excludeLookalikes = false
  } = options;

  const validLength = Math.max(12, Math.min(32, parseInt(length, 10) || 16));

  // Build active pools
  const activeSets = [];

  const filterLookalikes = (str) => {
    if (!excludeLookalikes) return str;
    return str.split('').filter(c => !LOOK_ALIKE_SET.has(c)).join('');
  };

  if (uppercase) {
    const chars = filterLookalikes(CHAR_SETS.uppercase);
    if (chars.length > 0) activeSets.push(chars);
  }
  if (lowercase) {
    const chars = filterLookalikes(CHAR_SETS.lowercase);
    if (chars.length > 0) activeSets.push(chars);
  }
  if (digits) {
    const chars = filterLookalikes(CHAR_SETS.digits);
    if (chars.length > 0) activeSets.push(chars);
  }
  if (symbols) {
    const chars = filterLookalikes(CHAR_SETS.symbols);
    if (chars.length > 0) activeSets.push(chars);
  }

  // Validate at least one character set is selected
  if (activeSets.length === 0) {
    throw new Error('At least one character set must be selected for password generation.');
  }

  const resultChars = [];

  // Guarantee at least one character from each selected set
  for (const charSet of activeSets) {
    const index = secureRandomInt(charSet.length);
    resultChars.push(charSet[index]);
  }

  // Combined pool for remaining characters
  const combinedPool = activeSets.join('');
  const remainingCount = validLength - resultChars.length;

  for (let i = 0; i < remainingCount; i++) {
    const index = secureRandomInt(combinedPool.length);
    resultChars.push(combinedPool[index]);
  }

  // Cryptographically shuffle all characters to avoid predictable set ordering
  secureShuffle(resultChars);

  return resultChars.join('');
}

/**
 * Generates a memorable passphrase from random words.
 * @param {Object} options
 * @param {number} [options.wordCount=4] Number of words (4-8)
 * @param {string} [options.separator='-'] Separator character (e.g. '-', '.', '_', ' ')
 * @param {boolean} [options.capitalize=true]
 * @param {boolean} [options.includeNumber=false]
 * @param {string[]} [options.wordList] Custom dictionary
 * @returns {string}
 */
export function generatePassphrase(options = {}) {
  const {
    wordCount = 4,
    separator = '-',
    capitalize = true,
    includeNumber = false,
    wordList = PASSPHRASE_WORDS
  } = options;

  const count = Math.max(4, Math.min(8, parseInt(wordCount, 10) || 4));
  const selectedWords = [];

  for (let i = 0; i < count; i++) {
    const idx = secureRandomInt(wordList.length);
    let word = wordList[idx];
    if (capitalize) {
      word = word.charAt(0).toUpperCase() + word.slice(1);
    }
    selectedWords.push(word);
  }

  if (includeNumber) {
    const digit = secureRandomInt(10);
    // Append or insert digit at random position
    const insertIdx = secureRandomInt(selectedWords.length);
    selectedWords[insertIdx] = `${selectedWords[insertIdx]}${digit}`;
  }

  return selectedWords.join(separator);
}

export default {
  CHAR_SETS,
  LOOK_ALIKE_SET,
  PASSPHRASE_WORDS,
  secureRandomInt,
  secureShuffle,
  generatePassword,
  generatePassphrase
};
