/**
 * @file tests/generator.test.js
 * @description Automated tests for PassGuard's cryptographically secure generator.
 * Asserts correct length, set constraints, guaranteed inclusion,
 * zero Math.random usage, and statistical uniformity over 10,000+ samples.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  generatePassword,
  generatePassphrase,
  secureRandomInt,
  CHAR_SETS,
  LOOK_ALIKE_SET
} from '../public/js/generator.js';

describe('PassGuard Cryptographic Generator Engine', () => {

  test('Generates password with exact requested length (12-32 range)', () => {
    for (const len of [12, 16, 20, 24, 32]) {
      const pwd = generatePassword({ length: len });
      assert.equal(pwd.length, len, `Expected length ${len}, got ${pwd.length}`);
    }
  });

  test('Guarantees at least one character from each selected set', () => {
    for (let i = 0; i < 50; i++) {
      const pwd = generatePassword({
        length: 16,
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: true
      });

      assert.ok(/[A-Z]/.test(pwd), 'Must contain uppercase');
      assert.ok(/[a-z]/.test(pwd), 'Must contain lowercase');
      assert.ok(/[0-9]/.test(pwd), 'Must contain digits');
      assert.ok(/[^a-zA-Z0-9]/.test(pwd), 'Must contain symbols');
    }
  });

  test('Contains ONLY the selected sets', () => {
    // Only lowercase and digits
    for (let i = 0; i < 20; i++) {
      const pwd = generatePassword({
        length: 16,
        uppercase: false,
        lowercase: true,
        digits: true,
        symbols: false
      });

      assert.ok(/^[a-z0-9]+$/.test(pwd), `Expected only lowercase & digits, got: ${pwd}`);
    }
  });

  test('Correctly excludes look-alike characters when option is enabled', () => {
    for (let i = 0; i < 30; i++) {
      const pwd = generatePassword({
        length: 24,
        excludeLookalikes: true
      });

      for (const char of pwd) {
        assert.ok(!LOOK_ALIKE_SET.has(char), `Look-alike character "${char}" found in: ${pwd}`);
      }
    }
  });

  test('Throws descriptive error when all sets are deselected', () => {
    assert.throws(() => {
      generatePassword({
        uppercase: false,
        lowercase: false,
        digits: false,
        symbols: false
      });
    }, /At least one character set must be selected/);
  });

  test('Passphrase mode generates correct word count and separators', () => {
    const phrase = generatePassphrase({ wordCount: 5, separator: '-' });
    const parts = phrase.split('-');
    assert.equal(parts.length, 5);
    for (const part of parts) {
      assert.ok(part.length > 0);
    }
  });

  test('Zero Math.random usage: Generator strictly uses Web Crypto API', () => {
    const originalMathRandom = Math.random;
    let mathRandomCalled = 0;

    Math.random = () => {
      mathRandomCalled++;
      return originalMathRandom();
    };

    try {
      for (let i = 0; i < 100; i++) {
        generatePassword({ length: 20 });
        generatePassphrase({ wordCount: 4 });
      }
      assert.equal(mathRandomCalled, 0, 'Math.random was invoked! Only crypto.getRandomValues is allowed.');
    } finally {
      Math.random = originalMathRandom;
    }
  });

  test('Statistical Uniformity: Chi-Square goodness-of-fit test over 10,000 samples', () => {
    const SAMPLE_COUNT = 10_000;
    const NUM_BUCKETS = 10;
    const counts = new Array(NUM_BUCKETS).fill(0);

    for (let i = 0; i < SAMPLE_COUNT; i++) {
      const num = secureRandomInt(NUM_BUCKETS);
      counts[num]++;
    }

    const expected = SAMPLE_COUNT / NUM_BUCKETS; // 1,000 per bucket
    let chiSquare = 0;

    for (let i = 0; i < NUM_BUCKETS; i++) {
      const observed = counts[i];
      const diff = observed - expected;
      chiSquare += (diff * diff) / expected;

      // Ensure no bucket deviates by more than 15% from expected
      const deviation = Math.abs(diff) / expected;
      assert.ok(
        deviation < 0.15,
        `Bucket ${i} count (${observed}) deviated by ${(deviation * 100).toFixed(1)}% (threshold: 15%)`
      );
    }

    // Critical value for Chi-Square distribution with 9 degrees of freedom at p = 0.001 is 27.88
    assert.ok(
      chiSquare < 27.88,
      `Chi-square value (${chiSquare.toFixed(2)}) exceeded critical threshold (27.88)`
    );
  });

});
