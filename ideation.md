# PassGuard — Ideation & Product Design Document

## 1. Executive Summary & Vision
**PassGuard** is a zero-knowledge, client-side password strength analyzer, cryptographically secure password generator, and interactive cybersecurity educational platform.

In modern cybersecurity, users face contradictory password advice: security teams demand complex symbols, while users respond with predictable patterns like `Password1!` or reuse the same password across dozens of online services. When breaches occur, credential stuffing botnets weaponize these habits to compromise entire digital identities.

PassGuard solves this through three core pillars:
1. **Mathematical Honesty (Zero-Knowledge & zxcvbn Dynamic Programming):** Passwords are never sent across the network. Entropy is calculated in real time using a dynamic programming pattern-matching engine that evaluates realistic dictionary, sequence, repetition, and keyboard-walk patterns.
2. **Tactile & Modern Aesthetics (Neumorphism + Glassmorphism):** An interface that combines tactile neumorphic controls (inset input wells, dual-shadow buttons, segmented meter tracks) with translucent glassmorphic surfaces (frosted floating cards, ambient drifting gradients).
3. **Cybersecurity Literacy:** Instead of displaying an opaque score or claiming a password is "unbreakable", PassGuard provides plain-English explanations, attack assumption models, an educational password reuse simulation, and interactive knowledge modules.

---

## 2. Target Audience & Personas
- **Students & Digital Citizens:** Require intuitive, non-technical explanations of entropy, length vs. complexity, and credential stuffing risks.
- **Security-Conscious Users & Developers:** Demand cryptographic integrity, verifiable client-side execution, rejection-sampled secure RNG, strict CSP hardening, and k-anonymity breach verification.
- **Accessibility & Assistive Tech Users:** Require high-contrast text ratios (WCAG AA), screen-reader live announcements, keyboard navigation, and reduced-motion options.

---

## 3. Product Principles
| Principle | Implementation |
| :--- | :--- |
| **Zero-Knowledge by Design** | Password strings, hashes, and derivatives (except the 5-char k-anonymity prefix) never touch the network, logs, or storage. All POST requests are explicitly rejected. |
| **Heuristic Humility** | No password is ever labelled "unbreakable" or "completely secure". Crack times and entropy are labelled as heuristic estimates under stated offline GPU attack models. |
| **Ephemeral Memory Safety** | Inputs, analysis results, and generated credentials auto-wipe on clear, reset, `pagehide`, and after 60 seconds of user inactivity. |
| **Tactile Precision** | Neumorphic elements provide physical tactile feedback; glassmorphic cards provide visual depth and hierarchical separation. |

---

## 4. Feature Ideation & User Journeys

### Journey 1: Real-Time Password Analysis
1. User enters a password into the neumorphic inset well.
2. Input is debounced by 40ms to maintain 60 FPS UI performance.
3. The engine decomposes the input into cheapest patterns (dictionary words, keyboard walks, repeated characters, sequences, dates, and predictable endings).
4. The 5-segment meter transitions smoothly with color-coded feedback (Very Weak, Weak, Fair, Strong, Very Strong).
5. The results panel displays entropy in bits, crack time under a 10¹⁰ guesses/sec offline GPU model, and plain-English feedback reasons.
6. The security checklist splits into completed versus pending criteria.

### Journey 2: Cryptographically Secure Password Generation
1. User selects between "Random Password" and "Memorable Passphrase".
2. User adjusts length slider (12–32 characters) or word count (4–8 words).
3. Secure generator uses `crypto.getRandomValues` with rejection sampling, guaranteeing uniform distribution without modulo bias.
4. Generated output is analyzed in real time with the analyzer to demonstrate its cryptographic strength.
5. User copies the credential to clipboard with single-click feedback and an automatic 30-second memory-clearing reminder.

### Journey 3: Educational Credential Stuffing Simulation
1. User inputs a sample fake account label (e.g. "Personal Email").
2. The simulation demonstrates the cascading domino effect of password reuse across email, banking, and cloud storage.
3. Emphasizes the golden rule: unique passwords per account coupled with a trusted password manager and MFA.

---

## 5. UI/UX Style Guide: Neumorphism + Glassmorphism Harmony
- **Neumorphism for Interactive Controls:**
  - Inset shadow wells for text inputs (`box-shadow: inset 4px 4px 8px ...`).
  - Dual light/dark shadows for tactile buttons, sliders, and checkboxes.
  - Active pressed states simulate physical depression.
- **Glassmorphism for Floating Surfaces:**
  - Header, hero card, results panel, generator card, and accordion panels use `backdrop-filter: blur(20px) saturate(140%)` with 1px light borders.
  - Ambient background with drifting purple (`#8b5cf6`), cyan (`#22d3ee`), and pink (`#ec4899`) blurred orbs provides rich color depth for the frosted glass to refract.
- **Dual Themes:**
  - **Dark Navy Glass:** Rich `#0a0f2c` to `#111a45` navy base.
  - **Light Lavender Neumorphic:** Soft `#e8ecf4` off-white base with frosted white glass and crisp contrast.
