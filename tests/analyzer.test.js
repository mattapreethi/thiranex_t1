/**
 * @file tests/analyzer.test.js
 * @description Comprehensive automated tests for PassGuard's password analyzer algorithm.
 * Uses Node's built-in node:test and node:assert modules.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { analyzePassword } from '../public/js/analyzer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load common wordlist for realistic test environment
const wordlistPath = join(__dirname, '..', 'server', 'data', 'common-passwords.json');
const wordlist = JSON.parse(readFileSync(wordlistPath, 'utf-8'));

describe('PassGuard Analyzer Engine', () => {

  test('Empty password: score 0, level Very Weak, helpful reason', () => {
    const res = analyzePassword('', wordlist);
    assert.equal(res.score, 0);
    assert.equal(res.level, 'Very Weak');
    assert.equal(res.entropy, 0);
    assert.ok(res.reasons.some(r => r.includes('No password entered') || r.includes('typing')));
  });

  test('Very short password ("a", "123"): score 0, level Very Weak, flagged as too short', () => {
    const res1 = analyzePassword('a', wordlist);
    assert.equal(res1.score, 0);
    assert.equal(res1.level, 'Very Weak');
    assert.ok(res1.reasons.some(r => r.includes('Too short')));

    const res2 = analyzePassword('123', wordlist);
    assert.equal(res2.score, 0);
    assert.equal(res2.level, 'Very Weak');
    assert.ok(res2.reasons.some(r => r.includes('Too short') || r.includes('sequential')));
  });

  test('Common password ("password"): score 0, level Very Weak, dictionary reason', () => {
    const res = analyzePassword('password', wordlist);
    assert.equal(res.score, 0);
    assert.equal(res.level, 'Very Weak');
    assert.ok(res.reasons.some(r => r.toLowerCase().includes('common') || r.toLowerCase().includes('password')));
  });

  test('Mandated specification: "Password1!" must score Very Weak with expected reason', () => {
    const res = analyzePassword('Password1!', wordlist);
    assert.equal(res.score, 0, 'Password1! must score 0');
    assert.equal(res.level, 'Very Weak', 'Password1! must be rated Very Weak');
    assert.ok(
      res.reasons.some(r => r.includes("Contains the common word 'password' with a predictable '1!' ending.")),
      `Expected plain-English reason not found in: ${JSON.stringify(res.reasons)}`
    );
  });

  test('Keyboard walk ("qwerty123"): score 0, level Very Weak, flags keyboard pattern', () => {
    const res = analyzePassword('qwerty123', wordlist);
    assert.equal(res.score, 0);
    assert.equal(res.level, 'Very Weak');
    assert.ok(res.reasons.some(r => r.toLowerCase().includes('keyboard') || r.toLowerCase().includes('common')));
  });

  test('Sequential characters ("abcd1234"): score 0, level Very Weak, flags sequence', () => {
    const res = analyzePassword('abcd1234', wordlist);
    assert.equal(res.score, 0);
    assert.equal(res.level, 'Very Weak');
    assert.ok(res.reasons.some(r => r.toLowerCase().includes('sequential')));
  });

  test('Repeating characters ("aaaaaaaaaaaa"): score 0, level Very Weak, flags repetition', () => {
    const res = analyzePassword('aaaaaaaaaaaa', wordlist);
    assert.equal(res.score, 0);
    assert.equal(res.level, 'Very Weak');
    assert.ok(res.reasons.some(r => r.toLowerCase().includes('repetitive')));
  });

  test('Long passphrase ("correct horse battery staple"): score >= 3 (Strong or Very Strong)', () => {
    const res = analyzePassword('correct horse battery staple', wordlist);
    assert.ok(res.score >= 3, `Expected score >= 3, received ${res.score} (${res.entropy} bits)`);
    assert.ok(['Strong', 'Very Strong'].includes(res.level));
    assert.ok(res.entropy >= 60, `Expected entropy >= 60 bits, received ${res.entropy}`);
  });

  test('20-character high-entropy random string ("k9#mP2$vL8@qW5!zR4^x"): level Very Strong', () => {
    const res = analyzePassword('k9#mP2$vL8@qW5!zR4^x', wordlist);
    assert.equal(res.score, 4);
    assert.equal(res.level, 'Very Strong');
    assert.ok(res.entropy >= 80, `Expected entropy >= 80 bits, received ${res.entropy}`);
    assert.ok(res.reasons.length > 0);
  });

  test('Mixed character types with under 10 chars: capped at Fair', () => {
    // "K8#mP2$" (7 chars) has high variety but short length
    const res = analyzePassword('K8#mP2$', wordlist);
    assert.ok(res.score <= 2, `Score under 10 chars must be <= 2, got ${res.score}`);
    assert.ok(['Very Weak', 'Weak', 'Fair'].includes(res.level));
    assert.ok(res.reasons.some(r => r.includes('Too short')));
  });

  test('Under 10 characters cap: never exceeds Fair', () => {
    const res = analyzePassword('aB3!xY9$', wordlist); // 8 chars
    assert.ok(res.score <= 2);
  });

});
