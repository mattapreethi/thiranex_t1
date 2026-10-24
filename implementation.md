# PassGuard — Implementation Details & Technical Walkthrough

## 1. Directory Structure

```
passguard/
├── package.json
├── .env.example
├── README.md
├── ideation.md
├── architecture.md
├── implementation.md
├── server/
│   ├── server.js                   # Application bootstrap & graceful shutdown
│   ├── config.js                   # Environment parsing and validation
│   ├── middleware/
│   │   ├── security.js             # Helmet CSP, Referrer-Policy, Permissions-Policy
│   │   ├── rateLimit.js            # express-rate-limit 60 req/min configuration
│   │   ├── logger.js               # Zero-knowledge sanitized request logging
│   │   └── errorHandler.js         # Centralized error handler without stack traces
│   ├── routes/
│   │   ├── health.js               # GET /api/health endpoint
│   │   ├── wordlist.js             # GET /api/wordlist with ETag & 304 revalidation
│   │   └── breachRange.js          # GET /api/breach-range/:prefix k-anonymity proxy
│   └── data/
│       └── common-passwords.json   # 500+ common passwords & keyboard walk datasets
├── public/
│   ├── index.html                  # Accessible semantic markup with skip link
│   ├── css/
│   │   ├── tokens.css              # Custom properties for dark/light themes
│   │   ├── base.css                # Fluid typography and accessible focus styles
│   │   ├── neumorphism.css         # Tactile dual-shadow and inset styles
│   │   ├── glass.css               # Frosted glass surfaces with solid fallbacks
│   │   ├── layout.css              # Mobile-first responsive Grid and Flexbox
│   │   └── animations.css          # GPU-accelerated orbs and micro-animations
│   ├── js/
│   │   ├── main.js                 # Application bootstrap & health ping
│   │   ├── analyzer.js             # DP pattern matching & entropy evaluation
│   │   ├── generator.js            # Rejection-sampled secure generator
│   │   ├── breach.js               # Web Crypto SHA-1 & k-anonymity client match
│   │   ├── ui.js                   # UI event orchestration & 60s inactivity wipe
│   │   ├── theme.js                # Dark/Light theme switching & localStorage
│   │   └── a11y.js                 # Throttled live announcements & accordion
│   └── assets/
│       └── logo.svg                # Scalable vector logo
└── tests/
    ├── analyzer.test.js            # 11 unit tests for analyzer
    ├── generator.test.js           # 8 tests for generator + uniformity + zero Math.random
    └── server.test.js              # 6 integration tests for server & zero-knowledge
```

---

## 2. Core Implementation Modules

### 2.1 Server Configuration (`server/config.js`)
Validates environment settings at startup:
- Ensures `PORT` is an integer between 1 and 65535.
- Parses `ENABLE_BREACH_CHECK` boolean flag.
- Exports an immutable `Object.freeze` configuration object.

### 2.2 Security Hardening Middleware (`server/middleware/security.js`)
Configured with strict Content Security Policy directives:
```javascript
helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  referrerPolicy: { policy: 'no-referrer' },
  xContentTypeOptions: true,
  xFrameOptions: { action: 'deny' }
})
```
Additionally enforces `Permissions-Policy` disabling camera, microphone, geolocation, and USB.

### 2.3 Zero-Knowledge Method Interceptor (`server/server.js`)
Guarantees that no route on the server accepts POST submissions:
```javascript
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({
      status: 405,
      error: 'Method Not Allowed. PassGuard operates under strict Zero-Knowledge principles and rejects data submissions.'
    });
  }
  next();
});
```

### 2.4 ETag & Caching in Wordlist Delivery (`server/routes/wordlist.js`)
Generates a SHA-256 ETag from the preloaded JSON content:
- Returns `Cache-Control: public, max-age=86400, stale-while-revalidate=3600`.
- Evaluates `If-None-Match` request header and sends `304 Not Modified` on cache hits, eliminating redundant data transfer.

---

## 3. Frontend Architecture

### 3.1 Analyzer Engine (`public/js/analyzer.js`)
- **De-leeting Normalization:** Converts `@` $\to$ `a`, `$` $\to$ `s`, `3` $\to$ `e`, `0` $\to$ `o`, `1` $\to$ `i` for dictionary matching without altering the original input string.
- **Pattern Matchers:** Identifies repeated runs, alphabetic/numeric sequences, keyboard walks, and dates.
- **Dynamic Programming Decomposition:** Computes the minimal guess cost across all possible segmentation paths.
- **Plain-English Feedback:** Builds non-echoing, actionable explanations (e.g., *"Contains the common word 'password' with a predictable '1!' ending"*).

### 3.2 Secure Generator Engine (`public/js/generator.js`)
- Employs 32-bit rejection sampling to guarantee uniform distribution across non-power-of-two alphabets.
- Ensures at least one character from each active character set (uppercase, lowercase, digits, symbols).
- Employs secure Fisher-Yates array shuffling using the same rejection-sampled RNG.
- Contains zero calls to `Math.random()`.

### 3.3 k-Anonymity Client Module (`public/js/breach.js`)
1. Calls `crypto.subtle.digest('SHA-1', new TextEncoder().encode(password))`.
2. Slices the 40-character hex string into a 5-character prefix and a 35-character suffix.
3. Requests `/api/breach-range/${prefix}`.
4. Searches the returned suffix list entirely within client browser memory.

### 3.4 Inactivity and Memory Sanitation (`public/js/ui.js`)
- Attaches listeners to `mousedown`, `keydown`, `touchstart`, and `scroll`.
- A 60-second inactivity timer clears all DOM inputs, analysis results, and generated credentials if no interaction occurs.
- Cleanses memory on the window `pagehide` event.

---

## 4. Design System Implementation

### Neumorphic Tactile Controls (`public/css/neumorphism.css`)
- **Dual Raised Shadows:** `-5px -5px 12px rgba(255, 255, 255, 0.04), 6px 6px 14px rgba(0, 0, 0, 0.6)`.
- **Inset Wells:** `box-shadow: inset 4px 4px 8px rgba(0, 0, 0, 0.65), inset -4px -4px 8px rgba(255, 255, 255, 0.03)`.
- **Active State:** Tactile depression effect on `:active` and `[aria-pressed="true"]`.

### Glassmorphic Surfaces (`public/css/glass.css`)
- **Blur & Saturation:** `backdrop-filter: blur(20px) saturate(140%)`.
- **Translucent Fill:** `rgba(16, 23, 62, 0.65)` on dark, `rgba(255, 255, 255, 0.65)` on light.
- **Fallbacks:** `@supports not (backdrop-filter: blur(1px))` provides opaque background fallbacks for older browsers.

---

## 5. Verification & Test Architecture

Run via `npm test` using Node.js's built-in `node:test` runner.

### Test Categories
1. **Analyzer Tests (`tests/analyzer.test.js`):**
   - Empty, single character, common passwords.
   - Mandated test: `Password1!` must score `0` (Very Weak) with exact plain-English reason.
   - Keyboard walk (`qwerty123`), sequence (`abcd1234`), repeat (`aaaaaaaaaaaa`).
   - Long passphrases (`correct horse battery staple`) and 20-character random strings.
   - Under 10 characters cap assertions.
2. **Generator Tests (`tests/generator.test.js`):**
   - Exact length compliance.
   - Guaranteed character set representation.
   - Look-alike character exclusion (`0O1lI|`).
   - Chi-Square goodness-of-fit test over 10,000 samples ($\chi^2 < 27.88$, max deviation $< 15\%$).
   - Verification of zero `Math.random` invocations.
3. **Server Tests (`tests/server.test.js`):**
   - Starts on ephemeral port (port 0).
   - `/api/health` 200 response with uptime and version.
   - `/api/wordlist` ETag generation and 304 revalidation.
   - `/api/breach-range/:prefix` 400 rejection of invalid prefixes.
   - Security headers verification.
   - Zero-Knowledge POST rejection (404/405).
   - Rate limiting 429 verification.
