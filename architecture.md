# PassGuard — Architectural Specification

## 1. System Overview & Component Diagram

PassGuard uses a strict **Zero-Knowledge Architecture** where the client browser performs 100% of password evaluation, entropy computation, and credential generation. The backend functions strictly as a static asset server and a privacy-preserving k-anonymity proxy.

```
+-----------------------------------------------------------------------------------+
|                                  USER BROWSER                                     |
|                                                                                   |
|  [ User Input ]  <==== NEVER SENT OVER NETWORK ====> [ Memory Cleaners ]          |
|         |                                            - 60s Inactivity Timer       |
|         v                                            - pagehide Wipe              |
|  [ analyzer.js ]                                     - Reset / Clear              |
|    |--> Normalization & Leetspeak Mapping                                         |
|    |--> Overlapping Pattern Search (Dict, Keyboard, Sequence, Repeat, Date)       |
|    |--> Dynamic Programming Minimum Guesses Solver                                |
|    `--> Entropy = log2(Guesses) & Crack Time (10^10 guesses/sec)                 |
|                                                                                   |
|  [ generator.js ]                                                                 |
|    |--> Web Crypto API (crypto.getRandomValues)                                   |
|    |--> 32-bit Rejection Sampling (Zero Modulo Bias)                             |
|    `--> Fisher-Yates Secure Array Shuffling                                       |
|                                                                                   |
|  [ breach.js (Optional Opt-In) ]                                                  |
|    |--> SHA-1 Digest computed via crypto.subtle.digest                            |
|    |--> Prefix: First 5 Hex Chars (e.g., "21BD1") ------------------------+      |
|    `--> Suffix: Remaining 35 Hex Chars <=== LOCAL CLIENT MATCH ONLY ===+   |      |
+------------------------------------------------------------------------|---|------+
                                                                         |   |
                                       GET /api/breach-range/:prefix     |   |
                                       (Only 5-char prefix transmitted)  |   |
                                                                         v   |
+----------------------------------------------------------------------------|------+
|                                NODE.JS EXPRESS BACKEND                     |      |
|                                                                            |      |
|  [ Security Middleware ]                                                   |      |
|    |--> Helmet Strict CSP (default-src 'self', no inline scripts/styles)   |      |
|    |--> Express Rate Limiting (60 req/min/IP with 429 JSON)                |      |
|    |--> Zero-Knowledge Guard: ALL non-GET /api/* requests rejected (405)   |      |
|    `--> Request Logger: Strips query strings, headers & payloads           |      |
|                                                                            |      |
|  [ Endpoints ]                                                             |      |
|    |--> GET /api/health           -> Status, uptime, version               |      |
|    |--> GET /api/wordlist         -> Cached wordlist + ETag (304 reval)    |      |
|    `--> GET /api/breach-range/:p  -> Proxies with Add-Padding: true -------+      |
+-----------------------------------------------------------------------------------+
```

---

## 2. Zero-Knowledge Privacy Architecture

### Network Air-Gap for Sensitive Data
- **No Ingestion Routes:** The backend has no routes, controllers, or databases designed to receive passwords.
- **Strict Method Enforcement:** A top-level router intercepts any non-`GET` method (`POST`, `PUT`, `DELETE`, `PATCH`) aimed at `/api/*` and immediately returns `405 Method Not Allowed`.
- **Zero Logging:** The custom request logger records only `HTTP Method`, `Sanitized Path`, `Status Code`, and `Duration`. No query strings, headers, or request bodies are parsed or logged.

### Ephemeral In-Memory Lifecycle
1. **Clear & Reset Buttons:** Instantly nullify DOM input values and reset analysis state structures.
2. **`pagehide` Lifecycle Event:** Intercepts browser unload/tab switch and flushes sensitive string references immediately.
3. **60-Second Inactivity Timer:** User inactivity (keyboard, mouse, touch, scroll) triggers an automatic memory purge after 60 seconds with an accessible notice.
4. **Storage Isolation:** Neither passwords nor generated strings are ever written to `localStorage`, `sessionStorage`, or cookies. Only the UI theme preference (`passguard-theme`) is stored.

---

## 3. Dynamic Programming Scoring Algorithm (zxcvbn-Style)

### Phase 1: Input Normalization & Pattern Detection
The input string $S$ of length $N$ is scanned to detect overlapping patterns:
1. **Common Dictionary / breached words:** Matching against 500+ curated passwords, normalized through de-leeting (`@` $\to$ `a`, `0` $\to$ `o`, `3` $\to$ `e`, `1/!` $\to$ `i`, `5/$` $\to$ `s`, `7/+` $\to$ `t`).
2. **Repeating character runs:** Sequences of 3+ identical characters (`aaaa`, `1111`).
3. **Sequential characters:** Forward and reverse alphabetic (`abcd`, `dcba`) and numeric sequences (`1234`, `9876`).
4. **Keyboard walks:** QWERTY rows and diagonals (`qwerty`, `asdfgh`, `zxcvbn`, `1qaz2wsx`).
5. **Calendar dates and years:** 4-digit years (`1900`–`2099`).
6. **Predictable structural endings:** Suffixes like `1!`, `123!`, `2024`, `!` appended to words.

### Phase 2: Dynamic Programming State Transitions
Let $dp[i]$ represent the minimum estimated guesses required to account for the prefix $S[0 \dots i-1]$:
- **Base Case:** $dp[0] = 1$
- **Recurrence Relation:**
  $$dp[i] = \min \begin{cases} 
  dp[i-1] \times \text{poolSize} & \text{(Treat } S[i-1] \text{ as unmatched brute-force char)} \\ 
  dp[j] \times \text{patternGuesses}(j, i) & \forall \text{ pattern matches starting at } j \text{ and ending at } i 
  \end{cases}$$
where $\text{poolSize}$ is calculated based on the active character classes present in the password.

### Phase 3: Entropy Calculation & Tier Mapping
Total guesses $G = dp[N]$.
Shannon entropy in bits:
$$E = \log_2(\max(1, G))$$

Entropy is mapped into 5 heuristic tiers:
- **Level 0 — Very Weak:** $E < 28$ bits
- **Level 1 — Weak:** $28 \le E < 36$ bits
- **Level 2 — Fair:** $36 \le E < 60$ bits
- **Level 3 — Strong:** $60 \le E < 80$ bits
- **Level 4 — Very Strong:** $E \ge 80$ bits

#### Specific Security Capping Rules:
1. **Mandated Rule:** `Password1!` scores **Very Weak** ($0$ bits / Level 0) due to dictionary root + predictable ending.
2. **Common Password Cap:** Any password found on the common list is capped at **Weak** (Level 1) or lower.
3. **Short Length Cap:** Any password under 10 characters is capped at **Fair** (Level 2) or lower, regardless of symbol complexity.
4. **Micro Length Cap:** Any password under 6 characters is capped at **Very Weak** (Level 0).

### Phase 4: Offline Attack Model & Crack-Time Computation
- **Assumption:** High-performance offline brute-force attack running at $10^{10}$ ($10$ billion) guesses/second (equivalent to a modern multi-GPU rig cracking fast hashes like MD5 or NTLM).
- **Time in seconds:** $T = G / 10^{10}$.
- Human-formatted into instant, seconds, minutes, hours, days, months, years, or centuries.

---

## 4. Cryptographic Generator Design

### Uniform Random Integer via Rejection Sampling
Standard JavaScript `Math.random()` or modulo reduction (`buffer[0] % N`) introduces **modulo bias** whenever the range does not evenly divide $2^{32}$. PassGuard strictly uses 32-bit rejection sampling:

```javascript
export function secureRandomInt(maxExclusive) {
  if (maxExclusive <= 1) return 0;
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buffer = new Uint32Array(1);

  while (true) {
    crypto.getRandomValues(buffer);
    const value = buffer[0];
    if (value < limit) {
      return value % maxExclusive;
    }
  }
}
```

### Character Set Invariants & Fisher-Yates Shuffling
1. **Guaranteed Class Inclusion:** When uppercase, lowercase, numbers, or symbols are enabled, the generator guarantees at least one character from each active set.
2. **Rejection-Sampled Fisher-Yates:** Shuffles the final array uniformly to prevent predictable character set locations:
   $$\forall i \in [N-1, 1], \quad j = \text{secureRandomInt}(i + 1), \quad \text{swap}(arr[i], arr[j])$$

---

## 5. k-Anonymity Breach Verification Model

```
Browser                          PassGuard Backend                 HIBP Upstream
  |                                     |                                |
  |-- 1. Compute SHA-1(password)        |                                |
  |      Result: 21BD19B64E...          |                                |
  |                                     |                                |
  |-- 2. GET /api/breach-range/21BD1 -->|                                |
  |      (Only 5-char prefix)           |-- 3. GET /range/21BD1 -------->|
  |                                     |      Add-Padding: true         |
  |                                     |      5-second timeout          |
  |                                     |<-- 4. Returns Suffix List -----|
  |<-- 5. Returns Suffix List ----------|                                |
  |                                                                      |
  |-- 6. Match suffix locally:                                           |
  |      Does list contain 9B64E...?                                     |
  |      --> YES: Found N times                                          |
  |      --> NO: Not found in dataset                                    |
```

Neither PassGuard's backend nor the upstream HaveIBeenPwned service ever receives the remaining 35 characters or the password plaintext.
